"""
Houses the wrapper for wmi-client.
There are a handful of injection vulnerabilities in this, so don't expose it
directly to end-users.
"""

import csv
import sh
import os
from StringIO import StringIO

class WmiClientWrapper(object):
    """
    Wrap wmi-client. Creating an instance of the wrapper will make a security
    context through which all future queries will be executed. It's basically
    just a convenient way to remember the username, password and host.
    There are a handful of injection vulnerabilities in this, so don't expose
    it directly to end-users.
    """

    def __init__(self, username="Administrator", password=None, host=None, delimiter="|",
                 workgroup=None, namespace="root\CIMV2", authenticationfile=None, debuglevel=None,
                 debugstderr=None, scope=None, kerberos=None, logbasename=None, leakreport=None,
                 maxprotocol=None, netbiosname=None):

        assert username
        assert password
        assert host # assume host is up

        # store the credentials for later
        self.username = username
        self.password = password
        self.host = host

        self.delimiter = delimiter
        self.workgroup = workgroup
        self.namespace = namespace
        self.authenticationfile = authenticationfile
        self.debuglevel = debuglevel
        self.debugstderr = debugstderr
        self.scope = scope
        self.kerberos = kerberos
        self.logbasename = logbasename
        self.leakreport = leakreport
        self.maxprotocol = maxprotocol
        self.netbiosname = netbiosname

    def _make_credential_args(self):
        """
        Makes credentials that get passed to wmic. This assembles a list of
        arguments.
        """
        arguments = []

        # the format is user%pass
        # NOTE: this is an injection vulnerability
        userpass = "--user={username}%{password}".format(
            username=self.username,
            password=self.password,
        )

        # userpass = "--user='{username}' --password='{password}'".format(
        #     username=self.username,
        #     password=self.password,
        # )


        arguments.append(userpass)

        # the format for ip addresses and host names is //
        hostaddr = "//{host}".format(host=self.host)

        arguments.append(hostaddr)

        return arguments

    def _setup_params(self):
        """
        Makes extra configuration that gets passed to wmic.
        """

        arguments = []



        # AUTHENTICATION FILE
        if self.authenticationfile is not None:
            authenticationfile_str = "--authentication-file='{authenticationfile}'".format(authenticationfile=self.authenticationfile)
            arguments.append(authenticationfile_str)

        # DELIMITER
        if self.delimiter is not None:
            delimiter_str = "--delimiter='{delimiter}'".format(delimiter=self.delimiter)
            arguments.append(delimiter_str)

        # DEBUG LEVEL
        if self.debuglevel is not None:
            debuglevel_str = "--debuglevel='{debuglevel}'".format(debuglevel=self.debuglevel)
            arguments.append(debuglevel_str)

        # DEBUG LEVEL
        if self.debugstderr is not None:
            debugstderr_str = "--debug-stderr='{debugstderr}'".format(debugstderr=self.debugstderr)
            arguments.append(debugstderr_str)

        # SCOPE
        if self.scope is not None:
            scope_str = "--scope='{scope}'".format(scope=self.scope)
            arguments.append(scope_str)

        # KERBEROS
        if self.kerberos is not None:
            kerberos_str = "--kerberos='{kerberos}'".format(kerberos=self.kerberos)
            arguments.append(kerberos_str)

        # LOG BASENAME --log-basename
        if self.logbasename is not None:
            logbasename_str = "--log-basename='{logbasename}'".format(logbasename=self.logbasename)
            arguments.append(logbasename_str)

        # LEAK REPORT leak-report
        if self.leakreport is not None:
            leakreport_str = "--leak-report='{leakreport}'".format(leakreport=self.leakreport)
            arguments.append(leakreport_str)

        # MAX PROTOCOL maxprotocol
        if self.maxprotocol is not None:
            maxprotocol_str = "--maxprotocol='{maxprotocol}'".format(maxprotocol=self.maxprotocol)
            arguments.append(maxprotocol_str)

        # NAMESPACE
        if self.namespace is not None:
            namespace_str = "--namespace='{namespace}'".format(namespace=self.namespace)
            print namespace_str
            arguments.append(namespace_str)

        # NETBIOSNAME
        if self.netbiosname is not None:
            netbiosname_str = "--netbiosname='{netbiosname}'".format(netbiosname=self.netbiosname)
            print netbiosname_str
            arguments.append(netbiosname_str)

        # WORKGROUP
        if self.workgroup is not None:
            workgroup_str = "--workgroup='{workgroup}'".format(workgroup=self.workgroup)
            arguments.append(workgroup_str)




        arguments = ' '.join(arguments)


        return arguments

    def _construct_query(self, klass):
        """
        Makes up a WMI query based on a given class.
        """
        # NOTE: this is an injection vulnerability
        queryx = "SELECT * FROM {klass}".format(klass=klass)
        return queryx

    def query(self, klass):
        """
        Executes a query using the wmi-client command.
        """
        # i don't want to have to repeat the -U stuff
        credentials = ' '.join(self._make_credential_args())

        # Let's make the query construction independent, but also if there's a
        # space then it's probably just a regular query.
        if " " not in klass:
            queryx = self._construct_query(klass)
        else:
            queryx = klass

        # and these are just configuration
        setup = self._setup_params()


        # queryx_str = ''.join(queryx)
        queryx_str = '"{}"'.format(''.join(queryx))


        # construct the arguments to wmic

        arguments = credentials + " " + setup + " " + queryx_str

        print "Arguments:"
        print arguments


        #output = os.system("/bin/wmic " + arguments)

        output = ""

        # f=os.popen("/bin/wmic " + arguments)
        f = os.popen("/usr/local/bin/wmic " + arguments)
        for i in f.readlines():
            print i
            output = output + i

        # and now parse the output
        return WmiClientWrapper._parse_wmic_output(output, delimiter=self.delimiter)

    @classmethod
    def _parse_wmic_output(cls, output, delimiter="|"):
        """
        Parses output from the wmic command and returns json.
        """
        # remove newlines and whitespace from the beginning and end
        output = output.strip()

        # Quick parser hack- make sure that the initial file or section is also
        # counted in the upcoming split.
        if output[:7] == "CLASS: ":
            output = "\n" + output

        # There might be multiple files in the output. Track how many there
        # should be so that errors can be raised later if something is
        # inconsistent.
        expected_sections_count = output.count("\nCLASS: ")

        # Split up the file into individual sections. Each one corresponds to a
        # separate csv file.
        sections = output.split("\nCLASS: ")

        # The split causes an empty string as the first member of the list and
        # it should be removed because it's junk.
        if sections[0] == "":
            sections = sections[1:]

        assert len(sections) is expected_sections_count

        items = []

        for section in sections:
            # remove the first line because it has the query class
            section = "\n".join(section.split("\n")[1:])

            strio = StringIO(section)

            moredata = list(csv.DictReader(strio, delimiter=delimiter))
            items.extend(moredata)

        # walk the dictionaries!
        return WmiClientWrapper._fix_dictionary_output(items)

    @classmethod
    def _fix_dictionary_output(cls, incoming):
        """
        The dictionary doesn't exactly match the traditional python-wmi output.
        For example, there's "True" instead of True. Integer values are also
        quoted. Values that should be "None" are "(null)".
        This can be fixed by walking the tree.
        The Windows API is able to return the types, but here we're just
        guessing randomly. But guessing should work in most cases. There are
        some instances where a value might happen to be an integer but has
        other situations where it's a string. In general, the rule of thumb
        should be to cast to whatever you actually need, instead of hoping that
        the output will always be an integer or will always be a string..
        """

        if isinstance(incoming, list):
            output = []

            for each in incoming:
                output.append(cls._fix_dictionary_output(each))

        elif isinstance(incoming, dict):
            output = dict()

            for (key, value) in incoming.items():
                if value == "(null)":
                    output[key] = None
                elif value == "True":
                    output[key] = True
                elif value == "False":
                    output[key] = False
                elif isinstance(value, str) and len(value) > 1 and value[0] == "(" and value[-1] == ")":
                    # convert to a list with a single entry
                    output[key] = [value[1:-1]]
                elif isinstance(value, str):
                    output[key] = value
                elif isinstance(value, dict):
                    output[key] = cls._fix_dictionary_output(value)

        return output

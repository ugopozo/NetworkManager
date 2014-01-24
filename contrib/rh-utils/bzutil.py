#!/usr/bin/env python

import sys
import string
import argparse
import subprocess
import os
import re
import kobo.xmlrpc
import xmlrpclib
import termcolor
from sets import Set
import ast
import datetime


devnull = open(os.devnull, 'w')

def _call(args):
    try:
        output = subprocess.check_output(args, stderr=devnull)
    except subprocess.CalledProcessError:
        print("Error invoking command: %s" % (' '.join(args)))
        sys.exit(1)
    return output

str_examples = string.replace(
"""Examples:
  * show general usage

      %cmd%

  * show help for subcommand

      %cmd% h p
      %cmd% p -h

  * parse BZ from commit messages, --ref accepts git revisions and ranges, see man gitrevisions(7)

      %cmd% p -c -e --ref origin/master~20.. --ref 4b39267

  * only show BZ list

      %cmd% p -c -e --ref origin/master~20..origin/master --list-by-bz

  * select BZ via command line

      %cmd% p -c -e --ref origin/master~20..origin/master --bz rh:100000,bg:670631 --bz 100001

  * blacklist some BZ

      %cmd% p -c -e --ref origin/master~20..origin/master --no-bz rh:100000,bg:670631

  * search open rhbz for the last 10 days

      %cmd% p -c -e --rh-search-since 10

  * search open rhbz since date

      %cmd% p -c -e --rh-search-since 20140110

  * the same search providing the full search options

      %cmd% p -c -e --rh-search "{'status': ['MODIFIED', 'POST', 'ON_QA'], 'component': ['NetworkManager'], 'last_change_time': '20140110'}"

  * be more verbose (add -v more then once)

      %cmd% p -c -e --ref origin/master~20..origin/master -v -v

  * show only the list-by-bz output

      %cmd% p -c -e --ref origin/master~20..origin/master --list-by-bz -v -v

  * set properies of matching BZ. Will show only what to do, unless run with --no-test.
    It will only change those properties, where it is possible and makes sense, e.g.
    setting cf_fixed_in only works, if the value is unset.
    Also, as always, you can combine --bz, --ref-, --rh-search, --rh-search-since,
    --no-bz at will.

      %cmd% p -c -e --ref origin/master~20..origin/master -v -v --set-status MODIFIED --set-cf-fixed-in 'NetworkManager-0.9.9.0-30.git20140108.el7'

""", "%cmd%", sys.argv[0]);


class ConfigStore:
    NAME_RHBZ_USER = 'rhbz_user'
    NAME_RHBZ_PASSWD = 'rhbz_passwd'
    NAMES = [
            NAME_RHBZ_USER,
            NAME_RHBZ_PASSWD,
        ]
    DEFAULT_FILE = '%s/.bzutil.conf' % os.path.expanduser("~")

    def __init__(self):
        self._initialized = False
    def setup(self, filename):
        if self._initialized:
            raise Exception("config: cannot initialize more then once")
        values = {}
        if not filename:
            if os.path.isfile(ConfigStore.DEFAULT_FILE):
                filename = ConfigStore.DEFAULT_FILE
        if filename:
            if not os.path.isfile(filename):
                raise Exception('config: file does not exist: %s. Use --conf to specify another file. Supported keys: [%s]' % (file,','.join(ConfigStore.NAMES)))
            with open(filename) as f:
                for line in f:
                    line = line.strip()
                    if not line or line[0] == '#':
                        continue
                    name, var = line.partition("=")[::2]
                    var = var.strip()
                    if var and ((var[0]=='"' and var[-1]=='"') or (var[0]=="'" and var[-1]=="'")):
                       var = var[1:-1]
                    values[name.strip()] = var
        self.filename = filename
        self.values = values
        self.v = {}
        self._initialized = True
    def get(self, key, default=None):
        if not self._initialized:
            raise Exception("config: cannot access the configuration before setup")
        if key in self.v:
            v = self.v[key]
            return v if v is not None else default

        ekey = "CONF_" + key
        v = os.environ.get(ekey)
        if v is None:
            v = self.values.get(key, None)
            if v is None:
                if default is None:
                    if self.filename:
                        raise Exception('config: Missing configuration value \'%s\': set it in the config file \'%s\' or set the environment variable \'%s\'' % (key, self.filename, ekey))
                    else:
                        raise Exception('config: Missing configuration value \'%s\': set it in the config file or set the environment variable \'%s\'' % (key, ekey))
        self.v[key] = v
        return v if v is not None else default
config = ConfigStore()

_colormap_flag = {
        '+': 'green',
        '?': 'yellow',
    }
_colormap_status = {
        'POST': 'green',
        'MODIFIED': 'yellow',
        'CLOSED': 'green',
    }
def _colored(colored, value, colormapping=None, prefix="", defaultcolor='red'):
    if not colored:
        return prefix + value
    if colormapping is not None:
        color = colormapping.get(value, defaultcolor)
    else:
        color = defaultcolor
    return termcolor.colored(prefix+value, color)


def git_ref_list(commit):
    return _call(['git', 'rev-list', '--no-walk', commit]).splitlines()

_git_commit_message = {}
def git_commit_message(shaid):
    if not _git_commit_message.has_key(shaid):
        _git_commit_message[shaid] = _call(['git', 'log', '--format=%B', '-n', '1', shaid])
    return _git_commit_message[shaid]

_git_summary = {}
def git_summary(commit, color=False, truncate_s=0):
    tag = (commit,color,truncate_s)
    if not _git_summary.has_key(tag):
        if truncate_s and truncate_s >= 2:
            truncate_s = '%%<(%s,trunc)' % truncate_s
        else:
            truncate_s = ''
        if color:
            pretty = '--pretty=format:%Cred%h%Creset %Cgreen(%ci)%Creset [%C(yellow)%an%Creset] '+truncate_s+'%s%C(yellow)%d%Creset'
        else:
            pretty = '--pretty=format:%h (%ci) [%an] ' + truncate_s + '%s%d'
        _git_summary[tag] = _call(['git', 'log', '-n1', pretty, '--abbrev-commit', '--date=local', commit])
    return _git_summary[tag]

_git_get_commit_date = {}
def git_get_commit_date(shaid):
    if not _git_get_commit_date.has_key(shaid):
        _git_get_commit_date[shaid] = int(_call(['git', 'log', '--format=%ct', '-n', '1', shaid]))
    return _git_get_commit_date[shaid]


class PasswordError(ValueError):
    pass


class CmdBase:
    def __init__(self, name):
        self.name = name
        self.parser = None

    def run(self, argv):
        print_usage()

def XMLRPCDateTime2datetime(dt):
    if isinstance(dt, datetime.datetime):
        return dt
    return datetime.datetime.strptime(dt.value, "%Y%m%dT%H:%M:%S")

# Webservice docs: http://www.bugzilla.org/docs/4.4/en/html/api/Bugzilla/WebService/Bug.html
class BzClient:
    COMMON_FIELDS = ['id', 'depends_on', 'blocks', 'flags', 'keywords', 'status', 'component']
    DEFAULT_FIELDS = ['summary', 'status', 'product', 'version', 'component', 'flags', 'cf_fixed_in']

    def __init__(self, url):
        transport = None
        use_https = False
        if url.startswith('https://'):
            transport = kobo.xmlrpc.SafeCookieTransport()
            use_https = True
        else:
            transport = kobo.xmlrpc.CookieTransport()
        self._key_part = (url, use_https)
        self._client = xmlrpclib.ServerProxy(url, transport=transport)

    def _login(self):
        if hasattr(self, '_login_called'):
            return
        self._user = config.get(ConfigStore.NAME_RHBZ_USER)
        self._password = config.get(ConfigStore.NAME_RHBZ_PASSWD)
        self._login_called = True
        self._client.User.login({'login': self._user,
                                 'password': self._password})

    _getBZDataCache = {}
    def getBZData(self, bzid):
        self._login()

        key = ( bzid, self._key_part, self._user, self._password )
        if BzClient._getBZDataCache.has_key(key):
            return BzClient._getBZDataCache[key]

        params = {
                'ids': bzid,
                'include_fields': BzClient.DEFAULT_FIELDS,
            }

        bugs_data = self._client.Bug.get(params)
        #print(bugs_data)
        bug_data = bugs_data['bugs'][0]
        BzClient._getBZDataCache[key] = bug_data
        return bug_data
    def clearBZData(self, bzid):
        key = ( bzid, self._key_part, self._user, self._password )
        if BzClient._getBZDataCache.has_key(key):
            del BzClient._getBZDataCache[key]

    def search(self, search_params):
        self._login()
        bugs_data = self._client.Bug.search(search_params)['bugs']
        for bug_data in bugs_data:
            key = ( bug_data['id'], self._key_part, self._user, self._password )
            BzClient._getBZDataCache[key] = bug_data
        return bugs_data

    def update(self, bzInfos, options, colored, no_test):
        bz = [(b, b.can_set(options)) for b in bzInfos if isinstance(b, BzInfoRhbz)]
        bz = [(b,tuple([(k,can[k]) for k in sorted(can.keys())])) for (b,can) in bz if can]

        if not bz:
            return True

        bz_grouped = {}
        for (b,can) in bz:
            key = tuple([(c[0],c[1][1]) for c in can])
            ll = bz_grouped.get(key, None)
            if ll is None:
                ll = []
                bz_grouped[key] = ll
            ll.append((b,can))
        for gr in bz_grouped:
            bz_grouped[gr] = sorted(bz_grouped[gr], key=lambda b:b[0])

        print("Set RHBZ options:")
        for gr in bz_grouped:
            for gri in gr:
                print("  '%s' => '%s'" % (gri[0], gri[1]))
            grv = bz_grouped[gr]
            for b in grv:
                print("      %-15s == %s" % (b[0], ", ".join([x[0]+":'" +x[1][0]+"'" for x in b[1]])))

            params = {
                'ids': [str(i[0].bzid) for i in grv],
            }
            for gri in gr:
                if gri[0] == 'status':
                    params[gri[0]] = gri[1]
                elif gri[0] == 'cf_fixed_in':
                    params[gri[0]] = gri[1]
                else:
                    raise Exception("Unexpected property")

            if not no_test:
                print("      %s" % _colored(colored, "nop: only show", defaultcolor='yellow'))
                continue

            #params = { 'ids':params['ids'] }
            result = self._client.Bug.update(params)
            result = result['bugs']
            print("      %s: %s" % (_colored(colored, "Response", defaultcolor='green'), repr(result)))
            print("      Results:")
            for res in result:
                bzid = res['id']
                bzobjs = [b[0] for b in grv if b[0].bzid == bzid]
                if not bzobjs:
                    print(_colored(colored,"          >> Strange, receive unmatching response: %s" % (res)))
                    continue
                print("          %s (last-change=%s)" % (", ".join([str(b) for b in bzobjs]), XMLRPCDateTime2datetime(res['last_change_time'])))
                c = res['changes']
                if not c:
                    print(_colored(colored,"              >> no change"))
                else:
                    for changed in c:
                        r = c[changed]
                        print("              %-15s == '%s' => '%s'" % (changed, r['removed'], r['added']))
                for bzobj in bzobjs:
                    bzobj.clearBZData()


def is_sequence(arg):
    return (not hasattr(arg, "strip") and
        hasattr(arg, "__getitem__") or
        hasattr(arg, "__iter__"))


# class to hold information about a bugzilla entry
class BzInfo:
    def __init__(self, bzid, bzdata=None):
        self.bzid = bzid
        if bzdata is not None:
            self._bzdata = bzdata
    @property
    def bztype(self):
        return None
    @property
    def url(self):
        return None
    def __cmp__(self, other):
        return cmp( (self.bztype, self.bzid), (other.bztype, other.bzid) )
    def __hash__(self):
        return hash( (self.bztype, self.bzid) )
    def __str__(self):
        return "%s #%s" % (self.bztype, self.bzid)
    def __repr__(self):
        return "(\"%s\", \"%s\")" % (self.bztype, self.bzid)

    def getBZData(self, field=None):
        if not hasattr(self, '_bzdata'):
            self._bzdata = self._fetchBZData()
        if self._bzdata is None:
            self._bzdata = {}
        if field is None:
            return self._bzdata
        return self._bzdata.get(field, None)
    def _fetchBZData(self):
        return None
    def to_string_tight(self, verbose, colored):
        if verbose == 1:
            return None
        return self.url
    def to_string(self, prefix, verbose, colored):
        i = "%-4s #%-8s" % (self.bztype, self.bzid)
        if colored:
            i = termcolor.colored(i, 'cyan')
        s = self.to_string_tight(verbose, colored)
        if s is None:
            s = ""
        else:
            s = " " + s
        s = prefix + ("bug: %s%s" % (i, s))
        return s
    def can_set(self, options):
        return {}
    def clearBZData(self):
        if hasattr(self, '_bzdata'):
            del self._bzdata


class BzInfoBgo(BzInfo):
    def __init__(self, bzid):
        BzInfo.__init__(self, int(bzid))
    @BzInfo.bztype.getter
    def bztype(self):
        return "bgo"
    @BzInfo.url.getter
    def url(self):
        return "https://bugzilla.gnome.org/show_bug.cgi?id=%s" % self.bzid

class BzInfoRhbz(BzInfo):
    def __init__(self, bzid, bzdata=None):
        BzInfo.__init__(self, int(bzid), bzdata)
    @BzInfo.bztype.getter
    def bztype(self):
        return "rhbz"
    @BzInfo.url.getter
    def url(self):
        return "https://bugzilla.redhat.com/show_bug.cgi?id=%s" % self.bzid

    BzClient = BzClient('https://bugzilla.redhat.com/xmlrpc.cgi')
    def _fetchBZData(self):
        return BzInfoRhbz.BzClient.getBZData(self.bzid)
    def clearBZData(self):
        BzInfo.clearBZData(self)
        BzInfoRhbz.BzClient.clearBZData(self.bzid)

    def to_string_tight(self, verbose, colored):
        if verbose != 1:
            return BzInfo.to_string_tight(self, verbose, colored)
        bzdata = self.getBZData()
        s = ''
        if 'product' in bzdata:
            v = bzdata['product']
            if v == 'Red Hat Enterprise Linux 7':
                v = 'el7'
            elif v == 'Red Hat Enterprise Linux 6':
                v = 'el6'
            elif v == 'Fedora':
                v = 'fc'
        else:
            v = "??"
        v = v + "-" + ",".join(bzdata.get('version',"??"))
        s = s + _colored(colored, v, defaultcolor='yellow');
        v = bzdata.get('status', None)
        if v:
            s = s + ' ' + _colored(colored, v, _colormap_status)
        else:
            s = s + ' ??'
        v = bzdata.get('cf_fixed_in', None)
        if v:
            s = s + "+fix"
        v = bzdata.get('flags', None)
        if v is not None:
            d = dict([ (flag['name'], flag['status']) for flag in v ])
            fl = []
            for k in [
                        ('rhel-7.0.0','7'),
                        ('rhel-6.5.0', '6'),
                        ('pm_ack', 'p'),
                        ('devel_ack', 'd'),
                        ('qa_ack', 'q'),
                    ]:
                val = d.get(k[0], None)
                if val is not None:
                    fl.append(k[1] + val)
            if fl:
                s = s + ' ' + ' '.join(fl)
        v = bzdata.get('summary', None)
        if v is not None:
            s = s + ' -- ' + v
        return s
    def to_string(self, prefix, verbose, colored):
        if verbose <= 1:
            s = BzInfo.to_string(self, prefix, verbose, colored)
        elif verbose == 2:
            s = BzInfo.to_string(self, prefix, verbose, colored)
            s = s + '\n' + prefix + "     " + self.to_string_tight(1, colored)
        else:
            s = BzInfo.to_string(self, prefix, verbose, colored)
            bzdata = self.getBZData()
            for k in CmdParseCommitMessage._order_keys(bzdata.keys(), BzClient.DEFAULT_FIELDS):
                if k == 'flags':
                    for flag in bzdata[k]:
                        s = s + '\n' + prefix + ("     %-20s = %s" % ('#'+flag['name'], _colored(colored,flag['status'], _colormap_flag, ">> ")))
                elif k == 'summary':
                    s = s + '\n' + prefix + ("     %-20s = \"%s\"" % (k, bzdata[k]))
                elif k == 'status':
                    s = s + '\n' + prefix + ("     %-20s = %s" % (k, _colored(colored, bzdata[k], _colormap_status, ">> ")))
                elif k == 'cf_fixed_in':
                    if bzdata[k]:
                        s = s + '\n' + prefix + ("     %-20s = %s" % (k, bzdata[k]))
                else:
                    v = bzdata[k]
                    if is_sequence(v):
                        v = ', '.join(v)
                    s = s + '\n' + prefix + ("     %-20s = %s" % (k, v))
        return s
    def can_set(self, options):
        bzdata = self.getBZData()

        can = { }
        for o in options:
            if o in bzdata:
                if o == 'status':
                    allowed = {
                                "MODIFIED": ['POST', 'ASSIGNED', 'NEW'],
                                "ASSIGNED": ['NEW'],
                            }
                    if bzdata[o] in allowed.get(options[o], {}):
                        can[o] = (bzdata[o], options[o])
                elif o == 'cf_fixed_in':
                    if not bzdata[o]:
                        can[o] = (bzdata[o], options[o])
        return can





class UtilParseCommitMessage:

    _patterns = [
            ('(^|\W)(?P<replace>(?P<type>bgo)[ ]?[#]?(?P<id>[0-9]{4,7}))($|\W)',                            lambda m: BzInfoBgo(m.group('id'))),
            ('(^|\W)(?P<replace>https://bugzilla\.gnome\.org/show_bug\.cgi\?id=(?P<id>[0-9]{4,7}))($|\W)',  lambda m: BzInfoBgo(m.group('id'))),
            ('(^|\W)(?P<replace>(?P<type>rh(bz)?)[ ]?[#]?(?P<id>[0-9]{4,7}))($|\W)',                        lambda m: BzInfoRhbz(m.group('id'))),
            ('(^|\W)(?P<replace>https://bugzilla\.redhat\.com/show_bug.cgi\?id=(?P<id>[0-9]{4,7}))($|\W)',  lambda m: BzInfoRhbz(m.group('id'))),
            ('(^|\W)(?P<replace>(bz|bug)[ ]?[#]?(?P<id>[0-9]{4,7}))($|\W)',                                 lambda m: BzInfoRhbz(m.group('id'))),
            ('(^|\W)(?P<replace>#(?P<id>[0-9]{4,7}))($|\W)',                                                lambda m: BzInfoRhbz(m.group('id'))),
        ]
    _patterns = [(re.compile(p[0]), p[1]) for p in _patterns]

    def __init__(self, commit, result=None, git_backend=True, commit_date=0, no_bz=None):
        self.commit = commit
        self._result = result
        self._git_backend = git_backend
        self._commit_date = commit_date
        self._no_bz = no_bz

    @property
    def result(self):
        if not self._result and self._git_backend:
            message = git_commit_message(self.commit)
            data = []

            while message:
                match = None;
                match_ctor = None

                # we iterate over the patterns and search for the match that starts at left most position.
                for pattern in UtilParseCommitMessage._patterns:
                    m = pattern[0].search(message);
                    if m is not None:
                        if match is None:
                            match = m
                            match_ctor = pattern[1]
                        elif m.start() < match.start():
                            match = m;
                            match_ctor = pattern[1]
                if match is None:
                    break
                m = match_ctor(match)
                if m:
                    if self._no_bz is None or m not in self._no_bz:
                        data.append(m)

                # remove everything before the end of the match 'replace' group.
                group = match.group('replace')
                assert group, "need a replace match group, otherwise there is an endless loop";
                message = message[match.end('replace'):];

            self._result = list(set(data))
        return self._result

    def __cmp__(self, other):
        if self._git_backend != other._git_backend:
            return cmp(self._git_backend, other._git_backend)
        return cmp(self.commit, other.commit)
    def __hash__(self):
        return hash(self.commit)
    def __str__(self):
        return str( (self.commit, self.result) )
    def __repr__(self):
        return str(self)

    def commit_summary(self, colored, shorten=False):
        if self._git_backend:
            s = "git:"
            if colored:
                s = termcolor.colored(s, 'red')
            return "ref: " + s + ' ' + git_summary(self.commit, colored, 50 if shorten else 0)
        s = self.commit
        if shorten and len(s) > 100:
            s = s[0:98] + ".."
        if colored:
            s = "ref: " + termcolor.colored(s, 'red')
        else:
            s = "ref: " + s
        return s
    def get_commit_date(self):
        if self._git_backend:
            return git_get_commit_date(self.commit)
        return self._commit_date





class CmdParseCommitMessage(CmdBase):

    def __init__(self, name):
        CmdBase.__init__(self, name)


        self.parser = argparse.ArgumentParser(prog=sys.argv[0] + " " + name, description="Parse commit messages.")
        self.parser.add_argument('--color', '-c', dest='color', action='store_true', help='colorize output')
        self.parser.add_argument('--conf', metavar='conf', default=None, help='config file (defaults to %s). Supported keys: [%s]' % (ConfigStore.DEFAULT_FILE, ','.join(ConfigStore.NAMES)))
        self.parser.add_argument('--ref', action='append', help='Specify refs to parse bz ids from the commit message, this can be any ref, including ranges.')
        self.parser.add_argument('--bz', action='append', help='Specify additional bugzilla numbers on command line '
                                                               'This is a comma separated list of bugs, in the format [type:]num, eg. rh:100000,bg:70000')
        self.parser.add_argument('--rh-search', action='append', help='Search Red Hat bugzilla with the given search expression. RH_SEARCH is a dictionary with search options in python syntax.')
        self.parser.add_argument('--rh-search-since', default=None, help="A shortcut for --rh-search that sets some default options and 'last_change_time'. Set it to a date in form '%%Y%%m%%d' or the number of days.")
        self.parser.add_argument('--no-bz', action='append', help='Specify bugzilla numbers that should be ignored.')
        self.parser.add_argument('--verbose', '-v', action='count', help='Increase verbosity (use more then once)')
        self.parser.add_argument('--list-refs', dest='list_refs', action='store_const', const=True, help='List the refs in the output')
        self.parser.add_argument('--list-by-ref', dest='list_by_refs', action='store_const', const=True, help='List sorted by refs')
        self.parser.add_argument('--list-by-bz', dest='list_by_bz', action='store_const', const=True, help='List sorted by BZ')
        self.parser.add_argument('--no-list-refs', dest='list_refs', action='store_const', const=False, help='disable --list-refs')
        self.parser.add_argument('--no-list-by-ref', dest='list_by_refs', action='store_const', const=False, help='disable --list-by-ref')
        self.parser.add_argument('--no-list-by-bz', dest='list_by_bz', action='store_const', const=False, help='disable --list-by-bz')
        self.parser.add_argument('--show-empty-refs', '-e', action='store_true', help='Show refs without bugs')
        self.parser.add_argument('--set-status', '-s', default=None, help='Set BZ status to the specified string (no action without --no-test)')
        self.parser.add_argument('--set-cf-fixed-in', '-m', default=None, help='Set BZ cf_fixed_in to the specified string (no action without --no-test)')
        self.parser.add_argument('--no-test', action='store_true', help='If specified any --set-* options, really change the bug')

    @staticmethod
    def _order_keys(keys, ordered):
        return [o for o in ordered if o in keys]

    def _parse_bz(self, obz, no_bz):
        bz_tuples = [bz for bz in re.split('[,; ]', obz) if bz]
        result_man2 = []
        has_any = False
        for bzii in bz_tuples:
            bzi = bzii.partition(':')
            if not bzi[1] and not bzi[2]:
                bzi = bzii.partition('#')
            if not bzi[1] and not bzi[2]:
                bzi = ['rh',bzi[0]]
            else:
                bzi = bzi[::2]
            if not bzi[0] or not bzi[1] or not re.match('^[0-9]{4,7}$', bzi[1]):
                raise Exception('invalid bug specifier \"%s\" (%s)' % (obz, bzii))
            bz = None
            if bzi[0] == 'rhbz' or bzi[0] == 'rh':
                bz = BzInfoRhbz(bzi[1])
            elif bzi[0] == 'bgo' or bzi[0] == 'bg':
                bz = BzInfoBgo(bzi[1])
            else:
                raise Exception('invalid bug specifier \"%s\"' % obz)
            if no_bz is None or bz not in no_bz:
                result_man2.append(bz)
            has_any = True
        if not has_any:
            raise Exception('invalid bug specifier \"%s\": contains no bugs' % obz)
        return result_man2
    def _parse_bzlist(self, bzlist, no_bz=None):
        i = 0
        result_man = []
        for obz in (bzlist if bzlist else []):
            result_man2 = self._parse_bz(obz, no_bz)
            result_man.append(UtilParseCommitMessage('bz:\"%s\"' % obz, result_man2, git_backend=False, commit_date=-1000+i))
            i = i + 1
        return result_man

    def _rh_search(self, params, no_bz=None):
        searches = BzInfoRhbz.BzClient.search(params)
        result = []
        for s in searches:
            bz = BzInfoRhbz(s['id'], bzdata=s)
            if no_bz is None or bz not in no_bz:
                result.append(bz)
        return result
    def _rh_searchlist(self, rh_searches, no_bz=None):
        i = 0
        result = []
        for (name,params) in rh_searches:
            result2 = self._rh_search(params, no_bz)
            if not name:
                name = ' ' + repr(params)
            else:
                name = name + ': ' + repr(params)
            result.append(UtilParseCommitMessage('srch:' + name, result2, git_backend=False, commit_date=-2000+i))
            i = i + 1
        return result

    def run(self, argv):
        printed_something = False

        self.options = self.parser.parse_args(argv)

        config.setup(self.options.conf)

        supported_set_status = ['MODIFIED', 'ASSIGNED']
        if self.options.set_status and self.options.set_status not in supported_set_status:
            print("Invalid argument --set-status \"%s\". Supported values are [ \"%s\" ]" % (self.options.set_status,
                "\", \"".join(supported_set_status)))
            raise Exception("Invalid argument --set-status \"%s\"" % self.options.set_status)


        if  self.options.list_refs is not None or \
            self.options.list_by_refs is not None or \
            self.options.list_by_bz is not None:
            if self.options.list_refs is None:
                self.options.list_refs = False
            if self.options.list_by_refs is None:
                self.options.list_by_refs = False
            if self.options.list_by_bz is None:
                self.options.list_by_bz = False

        no_bz = self._parse_bzlist(self.options.no_bz)
        no_bz = set([bz for commit_data in no_bz for bz in commit_data.result])

        rh_searches = []
        for s in (self.options.rh_search if self.options.rh_search else []):
            try:
                v = ast.literal_eval(s)
            except Exception, e:
                raise Exception("Error parsing --rh-search option as python dictionary (\"%s\")" % (s), e)
            if type(v) != dict:
                raise Exception("Error parsing --rh-search option: expects a python dictionary, instead found %s: \'%s\'" % (type(v), repr(v)));
            rh_searches.append(('full', v))
        if self.options.rh_search_since:
            s = self.options.rh_search_since
            if re.match('^20[0-9]{6}$', s):
                d = datetime.datetime.strptime(s, '%Y%m%d')
            elif re.match('^[0-9]{6}$', s):
                d = datetime.datetime.strptime(s, '%y%m%d')
            elif re.match('^[0-9]{1,3}$', s):
                d = datetime.date.today() - datetime.timedelta(days=int(s))
            else:
                raise Exception("Invalid RH_SEARCH_SINCE value %s" % s)
            rh_searches.append(('since ' + s,  {
                    'component': ['NetworkManager'],
                    'status': ['MODIFIED','POST','ON_QA'],
                    'last_change_time': d.strftime('%Y%m%d'),
                }))

        result_man = self._parse_bzlist(self.options.bz, no_bz)
        result_all = [ (ref, [UtilParseCommitMessage(commit, no_bz=no_bz) for commit in git_ref_list(ref)]) for ref in (self.options.ref if self.options.ref else [])]
        result_search = self._rh_searchlist(rh_searches, no_bz)

        if self.options.list_refs or (self.options.list_refs is None and result_all):
            print("=== List commit refs (%s) ===" % (len(result_all)))
            for ref_data in result_all:
                count = len([commit_data for commit_data in ref_data[1] if commit_data.result])
                print("refs: %s (%s%s)" % (ref_data[0], count, "+"+str(len(ref_data[1])-count)))
                for commit_data in ref_data[1]:
                    if self.options.show_empty_refs or commit_data.result:
                        print("  %s" % commit_data.commit_summary(self.options.color))
                        for result in commit_data.result:
                            print(result.to_string("    ", self.options.verbose, self.options.color))
            printed_something = True


        result_reduced = [ commit_data for ref_data in result_all for commit_data in ref_data[1] ]
        result_reduced = result_reduced \
                + [ commit_data for commit_data in result_man ] \
                + [ commit_data for commit_data in result_search ]
        result_reduced = sorted(set(result_reduced), key=lambda commit_data: commit_data.get_commit_date(), reverse=True)

        if self.options.list_by_refs or (self.options.list_by_refs is None and result_reduced):
            if printed_something:
                print
            count = len([commit_data for commit_data in result_reduced if commit_data.result])
            print('=== List BZ by ref (%s+%s) ===' % (count, len(result_reduced)-count))
            for commit_data in result_reduced:
                if self.options.show_empty_refs or commit_data.result:
                    print("  %s" % commit_data.commit_summary(self.options.color))
                    for result in commit_data.result:
                        print(result.to_string("    ", self.options.verbose, self.options.color))
            printed_something = True

        result_bz0 = result_man \
                + [ commit_data for ref_data in result_all for commit_data in ref_data[1] if commit_data.result] \
                + result_search
        result_bz = {}
        for commit_data in result_bz0:
            for result in commit_data.result:
                l = result_bz.get(result, None)
                if not l:
                    l = Set()
                    result_bz[result] = l
                l.add(commit_data)
        result_bz_keys = sorted(result_bz.keys(), key=lambda result: (result.bztype, result.bzid), reverse=True)
        if self.options.show_empty_refs:
            result_bz0 = [ commit_data for ref_data in result_all for commit_data in ref_data[1] if not commit_data.result] \
                    + [ commit_data for commit_data in result_man if not commit_data.result] \
                    + [ commit_data for commit_data in result_search if not commit_data.result]
        else:
            result_bz0 = []
        if self.options.list_by_bz or (self.options.list_by_bz is None and result_bz):
            if printed_something:
                print
            print('=== List by BZ (%s) ===' % (len(result_bz_keys)))
            for result in result_bz_keys:
                print(result.to_string("    ", self.options.verbose, self.options.color))
                for commit_data in sorted(result_bz[result], key=lambda commit_data: commit_data.get_commit_date(), reverse=True):
                    print("         %s" % commit_data.commit_summary(self.options.color, shorten=True))
            if result_bz0:
                print("    bug: --")
                for commit_data in result_bz0:
                    print("         %s" % commit_data.commit_summary(self.options.color, shorten=True))
            printed_something = True

        if not self.options.set_status and \
           not self.options.set_cf_fixed_in:
            return

        options = {
                'status': self.options.set_status,
                'cf_fixed_in': self.options.set_cf_fixed_in,
                }
        options = dict([(k,options[k]) for k in options if options[k] is not None])

        print
        print("Setting BZ options:")
        for option in sorted(options.keys()):
            print("  '%s' => '%s'" % (option, options[option]))

        set_data = [ (result, result.can_set(options)) for result in result_bz_keys ]

        print("Changes:")
        has_changes = False
        for result,can in sorted(set_data, key=lambda s: (sorted(s[1].keys()), s[0])):
            print(result.to_string("  ", 1, self.options.color))
            for c in sorted(can.keys()):
                print("     %-16s : \"%s\" => \"%s\"" % ('"'+c+'"', can[c][0], can[c][1]))
                has_changes = True

        if not has_changes:
            print(_colored(self.options.color, "No changes to set", defaultcolor='green'))
            return

        print
        BzInfoRhbz.BzClient.update(result_bz_keys, options, self.options.color, self.options.no_test);

        if not self.options.no_test:
            print(_colored(self.options.color, "Changes not set, run with --no-test", defaultcolor='green'))
            return


commands = {}

class CmdHelp(CmdBase):

    def __init__(self, name):
        CmdBase.__init__(self, name)

    def run(self, argv):
        print("%s [%s] [OPTIONS]" % (sys.argv[0], '|'.join(commands.keys())))
        if len(argv) >= 1:
            command = find_cmds_by_name(argv[0])
            if len(command) == 1:
                parser = command[0].parser
                if parser:
                    print
                    parser.print_help()
        print
        print str_examples;


def commands_add(name, t, realname=None):
    commands[name] = t(realname if realname else name)


commands_add('parse',       CmdParseCommitMessage)
commands_add('help',        CmdHelp)
commands_add('?',           CmdHelp, realname='help')
commands_add('-h',          CmdHelp, realname='help')
commands_add('--help',      CmdHelp, realname='help')


def find_cmds_by_name(command_name):
    return list([commands[cmd] for cmd in commands.keys() if cmd.startswith(command_name)])


def print_usage():
    CmdHelp("help").run([])




if len(sys.argv) < 2:
    print_usage()
    sys.exit(1)

commands_matches = find_cmds_by_name(sys.argv[1])
if len(commands_matches) == 0:
    print("Invalid command \"%s\". Try one of [ %s ]" % (sys.argv[1], ', '.join(commands.keys())))
    print_usage();
    sys.exit(1)
elif len(commands_matches) > 1:
    print("Invalid command \"%s\". Not exact match of [ %s ]" % (sys.argv[1], ', '.join(commands.keys())))
    print_usage();
    sys.exit(1)
else:
    commands_matches[0].run(sys.argv[2:])
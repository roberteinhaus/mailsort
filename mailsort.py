#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import datetime
import email
import json
import re
import sys
from optparse import OptionParser

LOGFILE = None
RULES = None
VERBOSE = False
DEFAULTDIR = ""


def compile_regexes(conditions):
    # Build all regexes for the given conditions and return them together with
    # their header
    regexes = []
    for condition in conditions:
        flags = re.MULTILINE | re.DOTALL
        if condition['ignorecase']:
            flags |= re.IGNORECASE
        compiledre = re.compile(
            "^.*%s.*$" %
            condition['regex'], flags)
        regexes.append((condition['header'], compiledre))
    return regexes


def load_rules():
    # load rules from file
    with open(RULES) as rules_file:
        return json.load(rules_file)


def process_mail(mailfile):
    try:
        log("checking new mail", 'INFO')
        msg = email.message_from_file(mailfile)

        # Load rules from file.
        rules = load_rules()

        for rule in rules:
            match = True
            tested = False

            if not rule['active']:
                continue

            log("testing rule '%s'" % rule['name'], 'DEBUG')
            # Compile all conditions for this rule.
            regexes = compile_regexes(rule['conditions'])

            for header, compiledre in regexes:
                tested = True
                try:
                    value = msg[header]
                except Exception as e:
                    tested = False
                    log("header '$s' not found!" % header, 'DEBUG')
                    break
                if compiledre.match(value) is None:
                    match = False
                    log("NO match for header '%s' with value '%s'" %
                        (header, value), 'DEBUG')
                    break
                else:
                    log("header '%s' matches with value '%s'" %
                        (header, value), 'DEBUG')

            # We check for 'tested' and 'match' to be sure we checked
            # something and did not encouter a no-match.
            # If we would omit the 'tested' here, a faulty rule could lead to
            # to its action beeing carried out.
            # i.e. for a rule with a non-existant header 'match' will never be
            # false, but we don't want this rule to be compliant
            if tested and match:
                action = rule['action']
                log("move mail to '%s' because rule '%s' matches" %
                    (action['destdir'], rule['name']), 'INFO')
                if action['mark_read']:
                    mark_read = "1"
                    log("mark mail as read", 'INFO')
                else:
                    mark_read = "0"
                return mark_read + ";." + action['destdir']
    # At this point we did not return with a match, so either something went
    # wrong, or we simply had no matching rule
    except Exception as e:
        log(e, 'ERROR')
    else:
        log("no matching filter found", 'WARNING')
    return DEFAULTDIR


def log(line, severity='INFO'):
    if LOGFILE is not None:
        if (severity == 'ERROR'
                or severity == 'WARNING'
                or severity == 'INFO'
                or VERBOSE):
            with open(LOGFILE, 'a') as logfile:
                timestamp = datetime.datetime.now().isoformat()
                logfile.write("%s %s\n" % (timestamp, line))


def main(args, mailfile):
    parser = OptionParser(description="""
    this is the mailsort.py main script
    """.strip())

    global LOGFILE
    global RULES
    global VERBOSE

    parser.add_option("--logfile",
                      dest="logfile",
                      action="store",
                      help="logfile",
                      default=None
                      )
    parser.add_option("--rules",
                      dest="rules",
                      action="store",
                      help="rules",
                      default=None
                      )
    parser.add_option("-v",
                      dest="verbose",
                      action="store_true"
                      )
    (options, args) = parser.parse_args(args)

    VERBOSE = options.verbose

    LOGFILE = options.logfile
    if LOGFILE is not None:
        LOGFILE = LOGFILE.lower()

    RULES = options.rules
    if RULES is not None:
        RULES = RULES.lower()
        return process_mail(mailfile)
    else:
        log("no rules provided, we can't sort anything")
        return DEFAULTDIR


if __name__ == '__main__':
    mailbox = main(sys.argv[1:], sys.stdin)
    print("%s" % mailbox)

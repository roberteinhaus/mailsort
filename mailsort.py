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
        log("checking new mail")
        msg = email.message_from_file(mailfile)

        # Load rules from file.
        rules = load_rules()

        for rule in rules:
            if not rule['active']:
                continue
            # Compile all conditions for this rule.
            regexes = compile_regexes(rule['conditions'])

            match = True
            tested = False
            for part in msg.walk():
                for headername, value in part.items():
                    for header, compiledre in regexes:
                        if headername == header:
                            tested = True
                            if compiledre.match(value) is None:
                                # At this point, we tested a header
                                # with no match, so the rule in general
                                # will not match and we can stop here testing
                                # for this rule.
                                match = False
                                break
                    if not match:
                        # Skip this rule, because it will not match.
                        break
                if not match:
                    # Skip this rule, because it will not match.
                    break
            # We check for 'tested' and 'match' to be sure we checked
            # something and did not encouter a no-match.
            # If we would omit the 'tested' here, a faulty rule could lead to
            # to its action beeing carried out.
            # i.e. for a rule with a non-existant header 'match' will never be
            # false, but we don't want this rule to be compliant
            if tested and match:
                action = rule['action']
                log("move mail to '%s' because rule '%s' matches" %
                    (action['destdir'], rule['name']))
                if action['mark_read']:
                    mark_read = "1"
                    log("mark mail as read")
                else:
                    mark_read = "0"
                return mark_read + ";." + action['destdir']
    # At this point we did not return with a match, so either something went
    # wrong, or we simply had no matching rule
    except Exception as e:
        log(e)
    else:
        log("no matching filter found")
    return DEFAULTDIR


def log(line):
    if LOGFILE is not None:
        with open(LOGFILE, 'a') as logfile:
            timestamp = datetime.datetime.now().isoformat()
            logfile.write("%s %s\n" % (timestamp, line))


def main(args, mailfile):
    parser = OptionParser(description="""
    this is the mailsort.py main script
    """.strip())

    global LOGFILE
    global RULES

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
    (options, args) = parser.parse_args(args)

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

import argparse
import logging
from cbapi.defense import Policy, CbDefenseAPI
import time
import sys
import json
import unicodecsv
import os


log = logging.getLogger(__name__)


def get_cb_defense_object(args):
    if args.cburl and args.apitoken:
        cb = CbDefenseAPI(url=args.cburl, token=args.apitoken, ssl_verify=(not args.no_ssl_verify))
    else:
        cb = CbDefenseAPI(profile=args.profile)
    return cb



def get_policy_by_name_or_id(cb, policy_id=None, name=None):
     policies = []
     try:
         if policy_id:
             if isinstance(policy_id, list):
                 attempted_to_find = "IDs of {0}".format(", ".join([str(pid) for pid in policy_id]))
                 policies = [p for p in cb.select(Policy) if p.id in policy_id]
             else:
                 attempted_to_find = "ID of {0}".format(policy_id)
                 policies = [cb.select(Policy, policy_id, force_init=True)]
         elif name:
             if isinstance(name, list):
                 attempted_to_find = "names of {0}".format(", ".join(name))
                 policies = [p for p in cb.select(Policy) if p.name in name]
             else:
                 attempted_to_find = "name {0}".format(name)
                 policies = [p for p in cb.select(Policy) if p.name == name]

     except Exception as e:
            print("Could not find policy with {0}: {1}".format(attempted_to_find, str(e)))
     return policies







def list_policies(cb):
    for p in cb.select(Policy):
        print("Policy id {0}: {1} {2}".format(p.id, p.name, "({0})".format(p.description) if p.description else ""))
        # print("Rules:")
        # for r in p.rules.values():
        # print("  {0}: {1} when {2} {3} is {4}".format(r.get('id'), r.get("action"),
        # r.get("application", {}).get("type"),
        # r.get("application", {}).get("value"), r.get("operation")))


def import_policy(cb, parser, args):
    p = cb.create(Policy)

    p.policy = json.load(open(args.policyfile, "r"))
    p.description = args.description
    p.name = args.name
    p.priorityLevel = args.prioritylevel
    p.version = 2

    try:
        p.save()
    except ServerError as se:
        print("Could not add policy: {0}".format(str(se)))
    except Exception as e:
        print("Could not add policy: {0}".format(str(e)))
    else:
        print("Added policy. New policy ID is {0}".format(p.id))


def delete_policy(cb, parser, args):
    policies = get_policy_by_name_or_id(cb, args.id, args.name)
    if len(policies) == 0:
        return

    num_matching_policies = len(policies)
    if num_matching_policies > 1 and not args.force:
        print("{0:d} policies match and --force not specified. No action taken.".format(num_matching_policies))
        return

    for p in policies:
        try:
            p.delete()
        except Exception as e:
            print("Could not delete policy: {0}".format(str(e)))
        else:
            print("Deleted policy id {0} with name {1}".format(p.id, p.name))


def export_policy(cb, id, name):
    policies = get_policy_by_name_or_id(cb, id, name)
    for p in policies:
        timestr = time.strftime("%Y-%m-%d-%H-%M-%S")
        current_directory = os.getcwd()
        ensure_dir("Backups\\" + name)
        filename = os.path.join(current_directory, "Backups\\" + name + "\\" + name + "-" + timestr + ".json")
        print filename
        json.dump(p.policy, open(filename.format(p.id), "w"), indent=2)
        log.info("Wrote policy" + name + "to file " + filename)


def backup_policy(cb, id, name):
    policies = get_policy_by_name_or_id(cb, id, name)
    for p in policies:
        timestr = time.strftime("%Y-%m-%d-%H-%M-%S")
        current_directory = os.getcwd()
        ensure_dir("Backups\\" + name)
        filename = os.path.join(current_directory, "Backups\\" + name + "\\" + name + "-" + timestr + ".json")
        print filename
        json.dump(p.policy, open(filename.format(p.id), "w"), indent=2)
        log.info("Wrote policy" + name + "to file " + filename)


def add_rule(policy, action, type, application, operation):
    data = {"action": action, "application": {"type": type, "value": application}, "operation": operation,
            "required": 'false'}
    for element in policy:
        element.add_rule(data)
        log.info(
            "Added rule for: " + application + " with operation: " + operation + " and type: " + type + " and action: " + action)
        print "Added rule for: " + application + " with operation: " + operation + " and type: " + type + " and action: " + action


def _update_rule(policy, ruleID, action, type, application, operation):
    policy = policy[0]
    data = {"action": action, "application": {"type": type, "value": application}, "operation": operation,
            "required": 'false', "id": ruleID}
    policy.replace_rule(ruleID, data)
    log.info("Changed rule for application: " + application + " with operation: " + operation + " to action: " + action)
    print "Changed rule for application: " + application + " with operation: " + operation + " to action: " + action


def check_if_rule_exists(policy, type, application, operation, action):
    for element in policy:
        rules = element.policy
        # print type, application, operation, action
        for entry in rules["rules"]:
            if entry["application"]["type"] == type and entry["application"]["value"] == application and entry[
                "operation"] == operation and entry["action"] == action:
                # identical rules
                ret = []
                ret.append(1)
                break
            elif entry["application"]["type"] == type and entry["application"]["value"] == application and entry[
                "operation"] == operation:
                # action different
                log.info(
                    "Action for application " + application + " with type: " + type + "and operation: " + operation + " needs to be changed from: " +
                    entry["action"] + " to: " + action)
                ret = []
                ret.append(2)
                ret.append(entry["id"])
                break
            else:
                ret = []
                ret.append(3)
    return ret


def _UpdatePolicybyCSV(policy, csvfile):
    with open(csvfile, 'rb') as csvfile:
        reader = unicodecsv.DictReader(csvfile, encoding='utf-8-sig')
        length = len(reader.fieldnames)

        for i in xrange(5, length):
            for rule in reader:
                exists = check_if_rule_exists(policy, rule['Type'], rule['Application'], rule['Operation'], rule['Action'])
                if exists[0] == 1:
                    # print "rule already there nothing to do"
                    print ""
                elif exists[0] == 2:
                    print "rule needs to be updated"
                    # print exists[1]
                    _update_rule(policy, exists[1], rule['Action'], rule['Type'], rule['Application'], rule['Operation'])
                else:
                    print "rule needs to be added"
                    add_rule(policy, rule['Action'], rule['Type'], rule['Application'], rule['Operation'])


def delete_old_rules(policy, csvfile):
    with open(csvfile, 'rb') as csvfile:
        reader = list(unicodecsv.DictReader(csvfile, encoding='utf-8-sig'))
        oldruleids = []
        for element in policy:
            rules = element.policy
        policyrules = list(rules['rules'])

        for i in xrange(0, len(policyrules)):
            oldruleids.append(policyrules[i]['id'])
            for x in xrange(0, len(reader)):
                if policyrules[i]['application']['value'] == reader[x]['Application'] and policyrules[i]['operation'] == \
                        reader[x]['Operation'] and policyrules[i]['action'] == reader[x]['Action']:
                    oldruleids.remove(policyrules[i]['id'])

    for id in oldruleids:
        Policy.delete_rule(policy[0], id)
        log.info("deleted rule with id: " + str(id))


def log_rules(policy):
    for element in policy:
        print element.name, element.id
    rules = element.policy
    for rule in rules["rules"]:
        log.info(rule)


def build_cli_parser(description="Cb Example Script"):
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument("--cburl", help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_argument("--apitoken", help="API Token for Carbon Black server")
    parser.add_argument("--no-ssl-verify", help="Do not verify server SSL certificate.", action="store_true",
                        default=False)
    parser.add_argument("--profile", help="profile to connect", default="default")
    parser.add_argument("--verbose", help="enable debug logging", default=False, action='store_true')
    return parser


def ensure_dir(folder):
    current_directory = os.getcwd()
    directory = os.path.join(current_directory, folder)
    if not os.path.exists(directory):
        os.makedirs(directory)



def main():

    ensure_dir("Log")

    timestr = time.strftime("%Y-%m-%d-%H-%M-%S")
    logfile = "log\\log" + timestr + ".log"
    hdlr = logging.FileHandler(logfile)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    log.addHandler(hdlr)
    log.setLevel(logging.INFO)
    ensure_dir("Backups")
    ensure_dir("Backups\\test")
    parser = build_cli_parser("Policy operations")
    commands = parser.add_subparsers(help="Policy commands", dest="command_name")

    list_command = commands.add_parser("list", help="List all configured policies")

    import_policy_command = commands.add_parser("import", help="Import policy from JSON file")
    import_policy_command.add_argument("-N", "--name", help="Name of new policy", required=True)
    import_policy_command.add_argument("-d", "--description", help="Description of new policy", required=True)
    import_policy_command.add_argument("-p", "--prioritylevel", help="Priority level (HIGH, MEDIUM, LOW)",
                                       default="LOW")
    import_policy_command.add_argument("-f", "--policyfile", help="Filename containing the JSON policy description",required=True)

    export_policy_command = commands.add_parser("export", help="Export policy to JSON file")
    export_policy_command.add_argument("-N", "--name", help="Name of policy", required=True)

    del_command = commands.add_parser("delete", help="Delete policies")
    del_policy_specifier = del_command.add_mutually_exclusive_group(required=True)
    del_policy_specifier.add_argument("-i", "--id", type=int, help="ID of policy to delete")
    del_policy_specifier.add_argument("-N", "--name", help="Name of policy to delete.")

    csvupdate_policy_command = commands.add_parser("csvupdate", help="Update policy-rules from CSV file")
    csvupdate_policy_command.add_argument("-N", "--name", help="Name of policy to update", required=True)
    csvupdate_policy_command.add_argument("-f", "--csvfile", help="CSV-File containing new rules", required=True)

    args = parser.parse_args()
    cb = get_cb_defense_object(args)

   #pol = get_policy_by_name_or_id(cb,'','CSV')


    if args.command_name == "list":
        return list_policies(cb)
    elif args.command_name == "import":
        return import_policy(cb, parser, args)
    elif args.command_name == "export":
        return export_policy(cb, '', args.name)
    elif args.command_name == "delete":
        return delete_policy(cb, parser, args)
    elif args.command_name == "csvupdate":
        log.info("Creating backup of policy")
        export_policy(cb, '', args.name)  # First create a backup of the policy
        policy = get_policy_by_name_or_id(cb, '', args.name)
        log.info("Rules of policy: " + args.name + " before update:")
        log_rules(policy)
        log.info("Staring to update rules of  policy: " + args.name)
        _UpdatePolicybyCSV(policy, args.csvfile)
        log.info("Finished to update rules of  policy: " + args.name)
        log.info("Starting to cleanup old rules of policy: " + args.name)
        delete_old_rules(policy, args.csvfile)
        log.info("Finished with cleanup of old rules of  policy: " + args.name)


if __name__ == "__main__":
    sys.exit(main())

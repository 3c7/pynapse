import io
import os
from argparse import ArgumentParser
from yaml import load, dump, Loader, Dumper
from pynapse.pynapse import Pynapse, SynapseNode
from urllib3 import disable_warnings

global CONFIG


def load_config():
    """Loads the config file"""
    global CONFIG
    with io.open(os.path.join(os.getenv("HOME"), ".syn", "pynapse.yml")) as cfg:
        CONFIG = load(cfg.read(), Loader)


def config(args):
    """Handles everything config related"""
    global CONFIG
    if args.set:
        if args.parameter != "ssl":
            CONFIG[args.parameter] = args.set
        else:
            CONFIG["ssl"] = False if args.set.lower() == "false" else True
        with io.open(os.path.join(os.getenv("HOME"), ".syn", "pynapse.yml"), "w") as cfg:
            cfg.write(dump(CONFIG))

    if args.parameter in CONFIG.keys():
        print(CONFIG[args.parameter])


def storm(args):
    """Executes a storm query."""
    try:
        if not CONFIG["ssl"]:
            disable_warnings()
        p = Pynapse(
            CONFIG["url"],
            CONFIG["user"],
            CONFIG["pass"],
            CONFIG["ssl"],
            args.verbose
        )
    except KeyError as ke:
        print(f"Missing important config parameters: {ke.args}")
        exit(-1)

    response = p.storm_raw_parsed(args.storm_query)
    tick, tock = response[0], response[-1]
    for node in response[1:-1]:
        if not isinstance(node, SynapseNode):
            continue
        print(f"{node.node_type}={node.node_value}")
        for prop, value in node.props.items():
            if prop[0] == ".":
                print(f"\t{prop}={value}")
                continue
            print(f"\t:{prop}={value}")
        for tag, range in node.tags.items():
            if not range[0] and not range[1]:
                print(f"\t#{tag}")
            else:
                print(f"\t#{tag} ({range[0]}, {range[1]})")

def main():
    load_config()
    parser = ArgumentParser(description="Pynypase cli")
    parser.add_argument("--config", "-c", type=str, help="Alternative path to config file. Default is HOME/.syn/pynapse.py")
    subparser = parser.add_subparsers(title="command", dest="command", required=True, help="Pynapse command")

    config_parser = subparser.add_parser("config")
    config_parser.add_argument("parameter", type=str, choices=["url", "user", "ssl", "pass"],
                               help="Config value to get/set")
    config_parser.add_argument("--set", type=str, help="Write new value to config parameter")

    storm_parser = subparser.add_parser("storm")
    storm_parser.add_argument("storm_query", type=str, help="Storm query")
    storm_parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode (no output)")
    storm_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()
    if args.command == "config":
        config(args)
    elif args.command == "storm":
        storm(args)

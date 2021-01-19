import requests
import json
from pynapse.exceptions import AuthenticationError, HTTPError, SynapseStormError
from ipaddress import ip_address
from typing import Union, Tuple
from pymisp import PyMISP, MISPAttribute, MISPObject
from datetime import datetime


class SynapseMessage(object):
    """Generic synapse message object for HTTP API responses."""
    message_type: str
    message_content: dict

    @staticmethod
    def from_string(message_string: str):
        m = SynapseMessage()
        data = json.loads(message_string)
        m.message_type = data[0]
        m.message_content = data[1]
        return m

    def __repr__(self):
        return f"<SynapseMessage message_type={self.message_type} message_content={self.message_content}>"


class SynapseNode(SynapseMessage):
    """Synapse node object."""

    def __init__(self, node_type: str = None, node_value: str = None, parsed_value: str = None, props: dict = None,
                 tags: dict = None):
        self.node_type = node_type
        self.node_value = node_value
        self.parsed_value = parsed_value
        self.props = props
        self.tags = tags

    @staticmethod
    def from_string(message_string: str):
        return SynapseNode.from_message(SynapseMessage.from_string(message_string))

    @staticmethod
    def from_message(message: SynapseMessage):
        n = SynapseNode()
        if message.message_type != "node":
            raise TypeError(f"Expecting message of type \"node\", got \"{message.message_type}\"")

        n.raw = message.message_content
        n.node_type, n.node_value = message.message_content[0]
        n.props = dict(message.message_content[1]["props"])
        n.tags = dict(message.message_content[1]["tags"])
        n.process_value()
        return n

    def process_value(self):
        """Parses a node's value and adds it as parsed_value property."""
        if self.node_type == "inet:ipv4":
            self.parsed_value = str(ip_address(self.node_value))
        else:
            self.parsed_value = ""

    def __repr__(self):
        return f"<SynapseNode " \
               f"node_type={self.node_type} " \
               f"node_value={self.node_value} " \
               f"parsed_value={self.parsed_value or None} " \
               f"props={self.props} " \
               f"tags={self.tags}>"


class SynapseError(SynapseMessage):
    """Represents an error message returned from the Synapse API."""
    error_type: str
    error_message: str

    @staticmethod
    def from_string(message_string: str):
        return SynapseError.from_message(SynapseMessage.from_string(message_string))

    @staticmethod
    def from_message(message: SynapseMessage):
        e = SynapseError()
        e.error_type = message.message_content[0]
        e.error_message = message.message_content[1].get("mesg", "No error message given.")
        return e

    def __repr__(self):
        return f"<SynapseError error_type={self.error_type} error_message=\"{self.error_message}\">"


class SynapsePrint(SynapseMessage):
    """Represents a Synapse print message"""
    message_content: str

    @staticmethod
    def from_string(message_string: str):
        pass

    @staticmethod
    def from_message(message: SynapseMessage):
        p = SynapsePrint()
        p.message_content = message.message_content["mesg"]
        return p

    def __repr__(self):
        return f"<SynapsePrint message_content={self.message_content}>"

    def __str__(self):
        return self.message_content


class Pynapse(object):
    """Vertex Synapse HTTP API Wrapper"""

    def __init__(self, url, user, password, ssl=True, debug=False):
        self.session = requests.Session()
        self.url = url
        self.user = user
        self.ssl = ssl
        self.debug = debug
        self._login(password)

    def __repr__(self):
        return f"<Pynapse url={self.url} user={self.user} debug={self.debug}>"

    def _login(self, password):
        """Send POST request to login API endpoint to authenticate the session."""
        response = self.session.post(self.url + "/api/v1/login", json={
            "user": self.user,
            "passwd": password
        }, verify=self.ssl)
        if response.status_code != 200:
            raise HTTPError(response.text)
        data = response.json()
        if data["status"] != "ok":
            raise AuthenticationError(response.text)

    def _debug(self, s):
        """Prints debug message"""
        if self.debug:
            print(f"[DEBU][{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] {s}")

    @staticmethod
    def _chop_messages(message_string: str):
        """Chops API responses"""
        cursor = 0
        counter = 0
        messages = []
        for idx, c in enumerate(message_string):
            if c == "[":
                counter += 1
            if c == "]":
                counter -= 1
            if counter == 0:
                messages.append(message_string[cursor:idx + 1])
                cursor = idx + 1
            if counter < 0:
                raise ValueError("Could not chop messages. Counter is below 0.")
        return messages

    @staticmethod
    def _parse_message(message_string: str):
        """Parses a single message and returns proper message object"""
        m = SynapseMessage.from_string(message_string)
        if m.message_type == "node":
            return SynapseNode.from_message(m)
        elif m.message_type == "err":
            return SynapseError.from_message(m)
        elif m.message_type == "print":
            return SynapsePrint.from_message(m)
        return m

    def storm_raw(self, storm_query: str):
        """Sends a cufstom storm query without further client side processing"""
        response = self.session.get(
            self.url + "/api/v1/storm",
            json={
                "query": storm_query
            },
            verify=self.ssl
        )
        return response.text

    def storm_raw_parsed(self, storm_query: str):
        """Sends a custom storm query and parses the answer messages into SynapseMessage object and prints them."""
        r = self.storm_raw(storm_query)
        message_strings = self._chop_messages(r)
        return [self._parse_message(message_string) for message_string in message_strings]

    def _add_node(self, ntype: str, nvalue: str, tags: list = None, seen: Tuple[str, str] = None, **kwargs):
        """Generic node adding function. Return node on success, raises SynapseStormError if Synapse responds with an
        error and returns False if no node given in the Synapse response."""
        query = f"[{ntype}={nvalue}"
        if seen:
            query += f" .seen=({seen[0]},{seen[1]})"
        for k, v in kwargs.items():
            query += f" :{k}=\"{v}\""
        if tags:
            for tag in tags:
                query += f" +#{tag}"
        query += "]"
        self._debug(f"Sending query: {query}")
        response = self.storm_raw_parsed(query)
        for message in response:
            if isinstance(message, SynapseError):
                raise SynapseStormError(f"{message.error_type}: {message.error_message}")

            if isinstance(message, SynapseNode):
                return message
        return False

    def add_node(self, node_type, node_value) -> SynapseNode:
        """Adds a node without props and tags."""
        return self._add_node(node_type, node_value)

    def delete_node(self, node_or_type: Union[SynapseNode, str], node_value: str = None) -> bool:
        """Deletes a node"""
        b = False
        response = []

        if isinstance(node_or_type, SynapseNode):
            response = self.storm_raw_parsed(f"{node_or_type.node_type}={node_or_type.node_value} | delnode")
        elif isinstance(node_or_type, str):
            if not node_value:
                raise ValueError("node_value must be given.")
            response = self.storm_raw_parsed(f"{node_or_type}={node_value} | delnode")
        else:
            TypeError("node_or_type is not SynapseNode or str.")

        for message in response:
            if isinstance(message, SynapseError):
                raise SynapseStormError(f"{message.error_type}: {message.error_message}")

            if message.message_type == "prop:del":
                b = True
        return b

    def get_node(self, node_type, node_value):
        """Retrieves a node"""
        n = None
        query = f"{node_type}={node_value}"
        response = self.storm_raw_parsed(query)
        for message in response:
            if isinstance(message, SynapseError):
                raise SynapseStormError(f"{message.error_type}: {message.error_message}")

            if isinstance(message, SynapseNode):
                n = message
        return n

    def get_nodes(self, query: str):
        """Get multiple nodes by storm query."""
        nodes = []
        response = self.storm_raw_parsed(query)
        for message in response:
            if isinstance(message, SynapseError):
                raise SynapseStormError(f"{message.error_type}: {message.error_message}")

            if isinstance(message, SynapseNode):
                nodes.append(message)
        return nodes

    def add_tag(self, tag: str, title: str = None, doc: str = None):
        """Adds a tag"""
        return self._add_node("syn:tag", tag, title=title, doc=doc)

    def add_tag_to_node(self, node: SynapseNode, tag: str):
        """Adds a tag to a given node, returns the node."""
        query = f"{node.node_type}={node.node_value} [+#{tag}]"
        response = self.storm_raw_parsed(query)
        for message in response:
            if isinstance(message, SynapseError):
                raise SynapseStormError(f"{message.error_type}: {message.error_message}")

            if isinstance(message, SynapseNode):
                return message
        raise KeyError(f"API response should contain a node, but hasn't: {response}")

    def add_tags_to_node(self, node: SynapseNode, tags: list):
        """Adds multiple tags to a node with a single query."""
        query = f"{node.node_type}={node.node_value} ["
        for tag in tags:
            query += f" +#{tag} "
        query += "]"
        response = self.storm_raw_parsed(query)
        for message in response:
            if isinstance(message, SynapseError):
                raise SynapseStormError(f"{message.error_type}: {message.error_message}")

            if isinstance(message, SynapseNode):
                return message
        raise KeyError(f"API response should contain a node, but hasn't: {response}")

    def add_nodes_from_misp_event(self, pymisp_instance: PyMISP, uuid: str, tags: list = []):
        """Adds nodes from a given MISP event to Synapse - HEAVILY WIP"""
        added_nodes = []
        tagged_nodes = []
        event = pymisp_instance.get_event(uuid, pythonify=True)
        for attrib in event.attributes:
            node_type, node_value = self._misp_attribute_to_type_and_value(attrib)
            self._debug(f"Going to create node: {node_type}={node_value}")
            fs, ls = None, None
            if attrib.first_seen:
                fs = attrib.first_seen.strftime("%Y-%m-%d %H:%M:%S")
            if attrib.last_seen:
                ls = attrib.last_seen.strftime("%Y-%m-%d %H:%M:%S")
            seen = (fs if fs else ls, ls if ls else fs)
            added_nodes.append(self._add_node(node_type, node_value, seen=seen))
        if len(tags) > 0:
            for node in added_nodes:
                self._debug(f"Adding tags {tags} to {node}")
                tagged_nodes.append(self.add_tags_to_node(node, tags))
        return added_nodes

    def _misp_attribute_to_type_and_value(self, attribute: MISPAttribute):
        if attribute.type in ["ip-dst", "ip-src"]:
            node_type = "inet:ipv4"
        elif attribute.type in ["domain", "hostname"]:
            node_type = "inet:fqdn"
        else:
            raise TypeError("MISP attribute type currently not supported.")
        return node_type, attribute.value

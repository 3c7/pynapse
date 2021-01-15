import requests
import json
from pynapse.exceptions import AuthenticationError, HTTPError, SynapseStormError
from ipaddress import ip_address


class SynapseMessage(object):
    message_type: str
    message_content: dict

    @staticmethod
    def from_string(message_string: str):
        """Create a list of message objects from a HTTP API response"""
        m = SynapseMessage()
        data = json.loads(message_string)
        m.message_type = data[0]
        m.message_content = data[1]
        return m

    def __repr__(self):
        return f"<SynapseMessage message_type={self.message_type} message_content={self.message_content}>"


class SynapseNode(SynapseMessage):
    node_type: str
    node_value: str
    tags: dict
    props: dict
    raw: str

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
        """Processes node value."""
        if self.node_type == "inet:ipv4":
            self.node_value = str(ip_address(self.node_value))

    def __repr__(self):
        return f"<SynapseNode node_type={self.node_type} node_value={self.node_value} props={self.props} " \
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


class Pynapse(object):
    """Vertex Synapse HTTP API Wrapper"""

    def __init__(self, url, user, password, ssl=True):
        self.session = requests.Session()
        self.url = url
        self.user = user
        self.ssl = ssl
        self._login(password)

    def __repr__(self):
        return f"<Pynapse url={self.url} user={self.user}>"

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
        return m

    def storm_raw(self, storm_query: str):
        """Sends a custom storm query without further client side processing"""
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

    def add_node(self, node_type, node_value) -> SynapseNode:
        """Adds a node without props and tags."""
        n = None
        response = self.storm_raw_parsed(f"[{node_type}={node_value}]")
        for message in response:
            if isinstance(message, SynapseError):
                raise SynapseStormError(f"{message.error_type}: {message.error_message}")

            if isinstance(message, SynapseNode):
                n = message
        return n

    def delete_node(self, node_type, node_value) -> bool:
        """Deletes a node"""
        b = False
        response = self.storm_raw_parsed(f"{node_type}={node_value} | delnode")
        for message in response:
            if isinstance(message, SynapseError):
                raise SynapseStormError(f"{message.error_type}: {message.error_message}")

            if message.message_type == "prop:del":
                b = True
        return b


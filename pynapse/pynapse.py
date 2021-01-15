import requests
import json
from pynapse.exceptions import AuthenticationError, HTTPError
from ipaddress import ip_address


class SynapseMessage(object):
    message_type: str
    message_content: dict

    @classmethod
    def from_string(cls, message_string: str):
        """Create a message object from a HTTP API response chunk"""
        if "][" in message_string:
            messages = []
            for line in message_string.replace("][", "]\xff\xff[").split("\xff\xff"):
                messages.append(SynapseMessage.from_string(line))
            return messages
        else:
            m = SynapseMessage()
            m.message_type = message_string[2:message_string.index("\"", 2)]
            tmp_content = message_string.split(",", 1)[1].strip()
            if tmp_content[-1] == "]":
                tmp_content = tmp_content[:-1]
            m.message_content = json.loads(tmp_content)
        return m

    def __repr__(self):
        return f"<SynapseMessage message_type={self.message_type} message_content={self.message_content}>"


class SynapseNode(object):
    node_type: str
    node_value: str
    tags: dict
    props: dict
    raw: str

    @classmethod
    def from_message(cls, message: SynapseMessage):
        n = SynapseNode()
        if message.message_type != "node":
            raise TypeError(f"Expecting message of type \"node\", got \"{message.message_type}\"")

        n.raw = message.message_content
        n.node_type, n.node_value = message.message_content[0]
        n.process_value()
        n.props = dict(message.message_content[1]["props"])
        n.tags = dict(message.message_content[1]["tags"])
        return n

    def process_value(self):
        """Processes node value."""
        if self.node_type == "inet:ipv4":
            self.node_value = str(ip_address(self.node_value))

    def __repr__(self):
        return f"<SynapseNode node_type={self.node_type} node_value={self.node_value} props={self.props} " \
               f"tags={self.tags}>"


class Pynapse(object):
    """Vertex Synapse HTTP API Wrapper"""

    def __init__(self, url, user, password, ssl=True):
        self.session = requests.Session()
        self.url = url
        self.user = user
        self.ssl = ssl
        self._login(password)

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
        messages = SynapseMessage.from_string(r)
        for m in messages:
            if m.message_type == "node":
                print(SynapseNode.from_message(m))
            else:
                print(m)

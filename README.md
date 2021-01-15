# Pynapse - a naive Synapse HTTP API client

Pre alpha stage HTTP API client for [Vertex Synapse](https://github.com/vertexproject/synapse/). Created this just for testing.

```python
from pynapse import Pynapse
p = Pynapse("https://192.168.0.251:4443", "user", "password", ssl=False)
p.storm_raw_parsed("inet:ipv4=127.0.0.1")
```
```
<SynapseMessage message_type=init message_content={'tick': 1610731339406, 'text': 'inet:ipv4=127.0.0.1', 'task': '19e591d8563172254584e30fc228addb'}>
<SynapseNode node_type=inet:ipv4 node_value=127.0.0.1 props={'.created': 1610730720164, 'type': 'loopback'} tags={'aka': [None, None], 'aka.nils': [None, None], 'aka.nils.thr': [None, None], 'aka.nils.thr.localghost': [None, None]}>
<SynapseMessage message_type=fini message_content={'tock': 1610731339407, 'took': 1, 'count': 1}>
```
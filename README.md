# Pynapse - a naive Synapse HTTP API client

Pre alpha stage HTTP API client for [Vertex Synapse](https://github.com/vertexproject/synapse/). Created this just for testing.

## Login
```python
from pynapse import Pynapse
p = Pynapse("https://1.2.3.4:4443", "user", "password", ssl=False)
print(p)
```
```
<Pynapse url=https://1.2.3.4:4443 user=user>
```
## Add/Delete Nodes
```python
from pynapse import Pynapse
p = Pynapse("https://1.2.3.4:4443", "user", "password", ssl=False)
n = p.add_node("inet:fqdn", "github.com")
print(n)
# Eiter
p.delete_node("inet:fqdn", "github.com")
# Or
p.delete_node(n)
```
```
<SynapseNode node_type=inet:fqdn node_value=github.com props={'.created': 1610747280973, 'host': 'github', 'domain': 'com', 'issuffix': 0, 'iszone': 1, 'zone': 'github.com'} tags={}>
True
```

## Add Tag to Nodes
```python
from pynapse import Pynapse
p = Pynapse("https://1.2.3.4:4443", "user", "password", ssl=False)
node = p.add_node("inet:url", "https://raw.githubusercontent.com/malicious_user_1234/project/template.dotm")
node = p.add_tag_to_node(node, "ttp.mitre.t1221")
print(node)
```
```
<SynapseNode node_type=inet:url node_value=https://raw.githubusercontent.com/malicious_user_1234/project/template.dotm parsed_value= props={'.created': 1610800865521, 'proto': 'https', 'path': '/malicious_user_1234/project/tempalte.dotm', 'params': '', 'fqdn': 'raw.githubusercontent.com', 'port': 443, 'base': 'https://raw.githubusercontent.com/malicious_user_1234/project/tempalte.dotm'} tags={'ttp': [None, None], 'ttp.mitre': [None, None], 'ttp.mitre.t1221': [None, None]}>
```
## Raw Storm commands
```python
from pynapse import Pynapse
p = Pynapse("https://1.2.3.4:4443", "user", "password", ssl=False)
response = p.storm_raw_parsed("help")
for message in response:
    print(message)
```
```
<SynapseMessage message_type=init message_content={'tick': 1610747169326, 'text': 'help', 'task': 'fcfaf9fc7f6d48ca2e38b7334e173818'}>
<SynapseMessage message_type=print message_content={'mesg': 'package: synapse'}>
<SynapseMessage message_type=print message_content={'mesg': 'background            : Execute a query pipeline as a background task.'}>
<SynapseMessage message_type=print message_content={'mesg': 'count                 : Iterate through query results, and print the resulting number of nodes'}>
<SynapseMessage message_type=print message_content={'mesg': 'cron.add              : Add a recurring cron job to a cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'cron.at               : Adds a non-recurring cron job.'}>
<SynapseMessage message_type=print message_content={'mesg': 'cron.cleanup          : Delete all completed at jobs'}>
<SynapseMessage message_type=print message_content={'mesg': 'cron.del              : Delete a cron job from the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'cron.disable          : Disable a cron job in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'cron.enable           : Enable a cron job in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'cron.list             : List existing cron jobs in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': "cron.mod              : Modify an existing cron job's query."}>
<SynapseMessage message_type=print message_content={'mesg': 'cron.stat             : Gives detailed information about a cron job.'}>
<SynapseMessage message_type=print message_content={'mesg': 'delnode               : Delete nodes produced by the previous query logic.'}>
<SynapseMessage message_type=print message_content={'mesg': 'dmon.list             : List the storm daemon queries running in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'edges.del             : Bulk delete light edges from input nodes.'}>
<SynapseMessage message_type=print message_content={'mesg': 'feed.list             : List the feed functions available in the Cortex'}>
<SynapseMessage message_type=print message_content={'mesg': 'graph                 : Generate a subgraph from the given input nodes and command line options.'}>
<SynapseMessage message_type=print message_content={'mesg': 'help                  : List available commands and a brief description for each.'}>
<SynapseMessage message_type=print message_content={'mesg': 'iden                  : Lift nodes by iden.'}>
<SynapseMessage message_type=print message_content={'mesg': 'layer.add             : Add a layer to the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'layer.del             : Delete a layer from the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'layer.get             : Get a layer from the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'layer.list            : List the layers in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'layer.set             : Set a layer option.'}>
<SynapseMessage message_type=print message_content={'mesg': 'lift.byverb           : Lift nodes from the current view by an light edge verb.'}>
<SynapseMessage message_type=print message_content={'mesg': 'limit                 : Limit the number of nodes generated by the query in the given position.'}>
<SynapseMessage message_type=print message_content={'mesg': 'macro.del             : Remove a macro definition from the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'macro.exec            : Execute a named macro.'}>
<SynapseMessage message_type=print message_content={'mesg': 'macro.get             : Display the storm query for a macro in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'macro.list            : List the macros set on the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'macro.set             : Set a macro definition in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'max                   : Consume nodes and yield only the one node with the highest value for a property or variable.'}>
<SynapseMessage message_type=print message_content={'mesg': 'merge                 : Merge edits from the incoming nodes down to the next layer.'}>
<SynapseMessage message_type=print message_content={'mesg': 'min                   : Consume nodes and yield only the one node with the lowest value for a property.'}>
<SynapseMessage message_type=print message_content={'mesg': 'model.deprecated.check: Check for lock status and the existance of deprecated model elements'}>
<SynapseMessage message_type=print message_content={'mesg': 'model.deprecated.lock : Edit lock status of deprecated model elements.'}>
<SynapseMessage message_type=print message_content={'mesg': 'model.deprecated.locks: Display lock status of deprecated model elements.'}>
<SynapseMessage message_type=print message_content={'mesg': 'model.edge.del        : Delete a global key-value pair for an edge verb in the current view.'}>
<SynapseMessage message_type=print message_content={'mesg': 'model.edge.get        : Retrieve key-value pairs an edge verb in the current view.'}>
<SynapseMessage message_type=print message_content={'mesg': 'model.edge.list       : List all edge verbs in the current view and their doc key (if set).'}>
<SynapseMessage message_type=print message_content={'mesg': 'model.edge.set        : Set an key-value for an edge verb that exists in the current view.'}>
<SynapseMessage message_type=print message_content={'mesg': 'movetag               : Rename an entire tag tree and preserve time intervals.'}>
<SynapseMessage message_type=print message_content={'mesg': 'parallel              : Execute part of a query pipeline in parallel.'}>
<SynapseMessage message_type=print message_content={'mesg': 'pkg.del               : Remove a storm package from the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'pkg.list              : List the storm packages loaded in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'pkg.load              : Load a storm package from an HTTP URL.'}>
<SynapseMessage message_type=print message_content={'mesg': 'ps.kill               : Kill a running task/query within the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'ps.list               : List running tasks in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'queue.add             : Add a queue to the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'queue.del             : Remove a queue from the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'queue.list            : List the queues in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'reindex               : Use admin privileges to re index/normalize node properties.'}>
<SynapseMessage message_type=print message_content={'mesg': 'scrape                : Use textual properties of existing nodes to find other easily recognizable nodes.'}>
<SynapseMessage message_type=print message_content={'mesg': 'service.add           : Add a storm service to the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'service.del           : Remove a storm service from the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'service.list          : List the storm services configured in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'sleep                 : Introduce a delay between returning each result for the storm query.'}>
<SynapseMessage message_type=print message_content={'mesg': 'spin                  : Iterate through all query results, but do not yield any.'}>
<SynapseMessage message_type=print message_content={'mesg': 'splice.list           : Retrieve a list of splices backwards from the end of the splicelog.'}>
<SynapseMessage message_type=print message_content={'mesg': 'splice.undo           : Reverse the actions of syn:splice runt nodes.'}>
<SynapseMessage message_type=print message_content={'mesg': 'sudo                  : Deprecated sudo command.'}>
<SynapseMessage message_type=print message_content={'mesg': 'tee                   : Execute multiple Storm queries on each node in the input stream, joining output streams together.'}>
<SynapseMessage message_type=print message_content={'mesg': 'tree                  : Walk elements of a tree using a recursive pivot.'}>
<SynapseMessage message_type=print message_content={'mesg': 'trigger.add           : Add a trigger to the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'trigger.del           : Delete a trigger from the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'trigger.disable       : Disable a trigger in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'trigger.enable        : Enable a trigger in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'trigger.list          : List existing triggers in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': "trigger.mod           : Modify an existing trigger's query."}>
<SynapseMessage message_type=print message_content={'mesg': 'uniq                  : Filter nodes by their uniq iden values.'}>
<SynapseMessage message_type=print message_content={'mesg': 'view.add              : Add a view to the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'view.del              : Delete a view from the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'view.exec             : Execute a storm query in a different view.'}>
<SynapseMessage message_type=print message_content={'mesg': 'view.fork             : Fork a view in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'view.get              : Get a view from the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'view.list             : List the views in the cortex.'}>
<SynapseMessage message_type=print message_content={'mesg': 'view.merge            : Merge a forked view into its parent view.'}>
<SynapseMessage message_type=print message_content={'mesg': 'view.set              : Set a view option.'}>
<SynapseMessage message_type=print message_content={'mesg': 'wget                  : Retrieve bytes from a URL and store them in the axon. Yields inet:urlfile nodes.'}>
<SynapseMessage message_type=print message_content={'mesg': ''}>
<SynapseMessage message_type=print message_content={'mesg': 'For detailed help on any command, use <cmd> --help'}>
<SynapseMessage message_type=fini message_content={'tock': 1610747169328, 'took': 2, 'count': 0}>
```
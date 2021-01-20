# Pynapse - a naive Synapse HTTP API client

Pre alpha stage HTTP API client for [Vertex Synapse](https://github.com/vertexproject/synapse/). Created this just for testing.

## Login
```python
from pynapse import Pynapse
p = Pynapse("https://1.2.3.4:4443", "user", "password")
print(p)
```
```
<Pynapse url=https://1.2.3.4:4443 user=user>
```
## Add/Delete Nodes
```python
from pynapse import Pynapse
p = Pynapse("https://1.2.3.4:4443", "user", "password")
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
p = Pynapse("https://1.2.3.4:4443", "user", "password")
node = p.add_node("inet:url", "https://raw.githubusercontent.com/malicious_user_1234/project/template.dotm")
node = p.add_tag_to_node(node, "ttp.mitre.t1221")
print(node)
```
```
<SynapseNode node_type=inet:url node_value=https://raw.githubusercontent.com/malicious_user_1234/project/template.dotm parsed_value= props={'.created': 1610800865521, 'proto': 'https', 'path': '/malicious_user_1234/project/tempalte.dotm', 'params': '', 'fqdn': 'raw.githubusercontent.com', 'port': 443, 'base': 'https://raw.githubusercontent.com/malicious_user_1234/project/tempalte.dotm'} tags={'ttp': [None, None], 'ttp.mitre': [None, None], 'ttp.mitre.t1221': [None, None]}>
```

## Add Blog posts
*Note: This just creates media:news node. No IOCs importet.*
```python
from pynapse import Pynapse
p = Pynapse("https://1.2.3.4:4443", "user", "password")
node = p.add_news_from_url("https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/", tags=["aka.crowdstrike.mal.sunspot"])
print(node)
```
```
<SynapseNode node_type=media:news node_value=bc9abf1be59ffce180251d4cce755fe2 parsed_value=None props={'.created': 1611149307265, 'url:fqdn': 'www.crowdstrike.com', 'url': 'https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/', 'title': 'sunspot malware: a technical analysis | crowdstrike', 'summary': 'In this blog, we offer a technical analysis of SUNSPOT, malware that was deployed into the build environment to inject this backdoor into the SolarWinds Orion platform.'} tags={'aka': [None, None], 'aka.crowdstrike': [None, None], 'aka.crowdstrike.mal': [None, None], 'aka.crowdstrike.mal.sunspot': [None, None]}>
```

## Raw Storm commands
```python
from pynapse import Pynapse
p = Pynapse("https://1.2.3.4:4443", "user", "password")
response = p.storm_raw_parsed("help")
for message in response:
    print(message.__repr__()) # Print the representation of SynapsePrint objects
```
```
<SynapseMessage message_type=init message_content={'tick': 1610806568629, 'text': 'help', 'task': 'a14a676dbf4408e51eef4032784e4a0d'}>
<SynapsePrint message_content=package: synapse>
<SynapsePrint message_content=background            : Execute a query pipeline as a background task.>
<SynapsePrint message_content=count                 : Iterate through query results, and print the resulting number of nodes>
<SynapsePrint message_content=cron.add              : Add a recurring cron job to a cortex.>
<SynapsePrint message_content=cron.at               : Adds a non-recurring cron job.>
<SynapsePrint message_content=cron.cleanup          : Delete all completed at jobs>
<SynapsePrint message_content=cron.del              : Delete a cron job from the cortex.>
<SynapsePrint message_content=cron.disable          : Disable a cron job in the cortex.>
<SynapsePrint message_content=cron.enable           : Enable a cron job in the cortex.>
<SynapsePrint message_content=cron.list             : List existing cron jobs in the cortex.>
<SynapsePrint message_content=cron.mod              : Modify an existing cron job's query.>
<SynapsePrint message_content=cron.stat             : Gives detailed information about a cron job.>
<SynapsePrint message_content=delnode               : Delete nodes produced by the previous query logic.>
<SynapsePrint message_content=dmon.list             : List the storm daemon queries running in the cortex.>
<SynapsePrint message_content=edges.del             : Bulk delete light edges from input nodes.>
<SynapsePrint message_content=feed.list             : List the feed functions available in the Cortex>
<SynapsePrint message_content=graph                 : Generate a subgraph from the given input nodes and command line options.>
<SynapsePrint message_content=help                  : List available commands and a brief description for each.>
<SynapsePrint message_content=iden                  : Lift nodes by iden.>
<SynapsePrint message_content=layer.add             : Add a layer to the cortex.>
<SynapsePrint message_content=layer.del             : Delete a layer from the cortex.>
<SynapsePrint message_content=layer.get             : Get a layer from the cortex.>
<SynapsePrint message_content=layer.list            : List the layers in the cortex.>
<SynapsePrint message_content=layer.set             : Set a layer option.>
<SynapsePrint message_content=lift.byverb           : Lift nodes from the current view by an light edge verb.>
<SynapsePrint message_content=limit                 : Limit the number of nodes generated by the query in the given position.>
<SynapsePrint message_content=macro.del             : Remove a macro definition from the cortex.>
<SynapsePrint message_content=macro.exec            : Execute a named macro.>
<SynapsePrint message_content=macro.get             : Display the storm query for a macro in the cortex.>
<SynapsePrint message_content=macro.list            : List the macros set on the cortex.>
<SynapsePrint message_content=macro.set             : Set a macro definition in the cortex.>
<SynapsePrint message_content=max                   : Consume nodes and yield only the one node with the highest value for a property or variable.>
<SynapsePrint message_content=merge                 : Merge edits from the incoming nodes down to the next layer.>
<SynapsePrint message_content=min                   : Consume nodes and yield only the one node with the lowest value for a property.>
<SynapsePrint message_content=model.deprecated.check: Check for lock status and the existance of deprecated model elements>
<SynapsePrint message_content=model.deprecated.lock : Edit lock status of deprecated model elements.>
<SynapsePrint message_content=model.deprecated.locks: Display lock status of deprecated model elements.>
<SynapsePrint message_content=model.edge.del        : Delete a global key-value pair for an edge verb in the current view.>
<SynapsePrint message_content=model.edge.get        : Retrieve key-value pairs an edge verb in the current view.>
<SynapsePrint message_content=model.edge.list       : List all edge verbs in the current view and their doc key (if set).>
<SynapsePrint message_content=model.edge.set        : Set an key-value for an edge verb that exists in the current view.>
<SynapsePrint message_content=movetag               : Rename an entire tag tree and preserve time intervals.>
<SynapsePrint message_content=parallel              : Execute part of a query pipeline in parallel.>
<SynapsePrint message_content=pkg.del               : Remove a storm package from the cortex.>
<SynapsePrint message_content=pkg.list              : List the storm packages loaded in the cortex.>
<SynapsePrint message_content=pkg.load              : Load a storm package from an HTTP URL.>
<SynapsePrint message_content=ps.kill               : Kill a running task/query within the cortex.>
<SynapsePrint message_content=ps.list               : List running tasks in the cortex.>
<SynapsePrint message_content=queue.add             : Add a queue to the cortex.>
<SynapsePrint message_content=queue.del             : Remove a queue from the cortex.>
<SynapsePrint message_content=queue.list            : List the queues in the cortex.>
<SynapsePrint message_content=reindex               : Use admin privileges to re index/normalize node properties.>
<SynapsePrint message_content=scrape                : Use textual properties of existing nodes to find other easily recognizable nodes.>
<SynapsePrint message_content=service.add           : Add a storm service to the cortex.>
<SynapsePrint message_content=service.del           : Remove a storm service from the cortex.>
<SynapsePrint message_content=service.list          : List the storm services configured in the cortex.>
<SynapsePrint message_content=sleep                 : Introduce a delay between returning each result for the storm query.>
<SynapsePrint message_content=spin                  : Iterate through all query results, but do not yield any.>
<SynapsePrint message_content=splice.list           : Retrieve a list of splices backwards from the end of the splicelog.>
<SynapsePrint message_content=splice.undo           : Reverse the actions of syn:splice runt nodes.>
<SynapsePrint message_content=sudo                  : Deprecated sudo command.>
<SynapsePrint message_content=tee                   : Execute multiple Storm queries on each node in the input stream, joining output streams together.>
<SynapsePrint message_content=tree                  : Walk elements of a tree using a recursive pivot.>
<SynapsePrint message_content=trigger.add           : Add a trigger to the cortex.>
<SynapsePrint message_content=trigger.del           : Delete a trigger from the cortex.>
<SynapsePrint message_content=trigger.disable       : Disable a trigger in the cortex.>
<SynapsePrint message_content=trigger.enable        : Enable a trigger in the cortex.>
<SynapsePrint message_content=trigger.list          : List existing triggers in the cortex.>
<SynapsePrint message_content=trigger.mod           : Modify an existing trigger's query.>
<SynapsePrint message_content=uniq                  : Filter nodes by their uniq iden values.>
<SynapsePrint message_content=view.add              : Add a view to the cortex.>
<SynapsePrint message_content=view.del              : Delete a view from the cortex.>
<SynapsePrint message_content=view.exec             : Execute a storm query in a different view.>
<SynapsePrint message_content=view.fork             : Fork a view in the cortex.>
<SynapsePrint message_content=view.get              : Get a view from the cortex.>
<SynapsePrint message_content=view.list             : List the views in the cortex.>
<SynapsePrint message_content=view.merge            : Merge a forked view into its parent view.>
<SynapsePrint message_content=view.set              : Set a view option.>
<SynapsePrint message_content=wget                  : Retrieve bytes from a URL and store them in the axon. Yields inet:urlfile nodes.>
<SynapsePrint message_content=>
<SynapsePrint message_content=For detailed help on any command, use <cmd> --help>
<SynapseMessage message_type=fini message_content={'tock': 1610806568631, 'took': 2, 'count': 0}>
```
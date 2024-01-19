
-- Scan notebook command history for potential paper cut issues
-- https://docs.databricks.com/en/compute/access-mode-limitations.html#compute-access-mode-limitations
-- This query 'overcounts' the paper cuts that might be encountered. There are complex DBR interactions with DBR 11, 12, 13 and 14
with paper_cut_patterns(
select col1 as pattern, col2 as issue FROM values
    ('hive_metastore.', 		'AF300 - 3 level namespace'),
    ('spark.catalog.', 			'AF301.1 - spark.catalog.x'),
    ('spark._jsparkSession.catalog',	'AF301.2 - spark.catalog.x'),
    ('spark._jspark', 			'AF302.1 - Spark Context'),
    ('spark._jvm',			'AF302.2 - Spark Context'),
    ('._jdf', 				'AF302.3 - Spark Context'),
    ('._jcol',				'AF302.4 - Spark Context'),
    ('spark.read.format("jdbc")', 	'AF304 - JDBC datasource'),
    ('dbutils.notebook.entry_point.getDbutils().notebook().getContext().toJson()','AF305.1 - getContext'),
    ('dbutils.notebook.entry_point.getDbutils().notebook().getContext()','AF305.2 - getContext'),
    ('spark.udf.registerJavaFunction',	'AF306 - Java UDF'),
    ('boto3', 				'AF307.1 - boto3'),
    ('s3fs', 				'AF307.2 - s3fs'),
    ('from graphframes', 		'AF308 - Graphframes'),
    ('pyspark.ml.', 			'AF309 - Spark ML'),
    ('applyInPandas', 			'AF310.1 - applyInPandas'),
    ('mapInPandas', 			'AF310.2 - mapInPandas'),
    ('dbutils.fs.', 			'AF311 - dbutils.fs'),
    ('dbutils.credentials.', 		'AF312 - credential passthrough') -- credential passthrough
),
sparkcontext (
    select explode(split("_jvm, _jvm.org.apache.log4j, emptyRDD, range, init_batched_serializer, parallelize, pickleFile, textFile, wholeTextFiles, binaryFiles, binaryRecords, sequenceFile, newAPIHadoopFile, newAPIHadoopRDD, hadoopFile, hadoopRDD, union, runJob, setSystemProperty, uiWebUrl, stop, setJobGroup, setLocalProperty, getConf",', ')) as pattern,
    					'AF303.1 - RDD' as issue
    UNION ALL
    select explode(split("from pyspark.sql import SQLContext, import org.apache.spark.sql.SQLContext, spark.sparkContext ", ', ')) as pattern,				'AF303.2 - SQLContext' as issue
),
streaming (
    select explode(split('.trigger(continuous, kafka.sasl.client.callback.handler.class, kafka.sasl.login.callback.handler.class, kafka.sasl.login.class, kafka.partition.assignment.strategy, kafka.ssl.truststore.location, kafka.ssl.keystore.location, cleanSource, sourceArchiveDir, applyInPandasWithState, .format("socket"), StreamingQueryListener',', ')) pattern,
    					'AF330 - Streaming' as issue
),
paper_cuts(
    select pattern, issue FROM paper_cut_patterns
    UNION ALL
    select concat('sc.',pattern) as pattern, issue FROM sparkcontext
    UNION ALL
    select pattern, issue FROM streaming
),
iteractive_cluster_commands (
    SELECT 
        a.request_params.notebookId as notebook_id, 
        a.request_params.clusterId as cluster_id, 
        a.user_identity.email,
        a.request_params.commandLanguage,
        a.request_params.commandText 
    FROM system.access.audit a
    JOIN system.compute.clusters as c
        ON c.cluster_source != 'JOB'
        AND (c.tags.ResourceClass is null OR c.tags.ResourceClass != "SingleNode")
        AND a.action_name = 'runCommand' 
        AND a.request_params.clusterId = c.cluster_id
    WHERE
        a.event_date >= DATE_SUB(CURRENT_DATE(), 90)
),
python_matcher(
    select 
    p.issue, 
    a.notebook_id, 
    a.cluster_id, 
    a.email,
    a.commandLanguage,
    a.commandText 
from iteractive_cluster_commands a
join paper_cuts p
    ON a.commandLanguage = 'python'
    AND contains(a.commandText, p.pattern)
),
scala_matcher(
    select
        'AF320 - scala/R' as issue,
        a.notebook_id, 
        a.cluster_id, 
        a.email, 
        a.commandText  
    FROM iteractive_cluster_commands a
    where a.commandLanguage in ('scala','r')
),
unions(
    SELECT issue, notebook_id, cluster_id, email, commandText FROM python_matcher
    UNION ALL
    SELECT issue, notebook_id, cluster_id, email, commandText FROM scala_matcher
)
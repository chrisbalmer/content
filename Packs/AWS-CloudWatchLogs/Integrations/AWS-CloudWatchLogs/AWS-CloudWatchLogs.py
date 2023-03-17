import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import date
from datetime import timedelta
from datetime import datetime

class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj):  # pylint: disable=E0202
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resourceIds = id_list.split(",")
    return resourceIds


def create_entry(title, data, ec):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, data) if data else 'No result were found',
        'EntryContext': ec
    }


def raise_error(error):
    return {
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': str(error)
    }


def create_log_group(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {'logGroupName': args.get('logGroupName')}

        if args.get('kmsKeyId') is not None:
            kwargs.update({'kmsKeyId': args.get('kmsKeyId')})

        response = client.create_log_group(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Group was created successfully"

    except Exception as e:
        return raise_error(e)


def create_log_stream(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'logStreamName': args.get('logStreamName')
        }
        response = client.create_log_stream(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Stream was created successfully"

    except Exception as e:
        return raise_error(e)


def delete_log_stream(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'logStreamName': args.get('logStreamName')
        }
        response = client.delete_log_stream(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Stream was Deleted successfully"

    except Exception as e:
        return raise_error(e)


def delete_log_group(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {'logGroupName': args.get('logGroupName')}
        response = client.delete_log_group(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Group was Deleted successfully"

    except Exception as e:
        return raise_error(e)


def filter_log_events(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )

        data = []
        kwargs = {'logGroupName': args.get('logGroupName')}

        if args.get('logStreamNames') is not None:
            kwargs.update({'logStreamNames': parse_resource_ids(args.get('logStreamNames'))})
        if args.get('startTime') is not None:
            kwargs.update({'startTime': int(args.get('startTime'))})
        if args.get('endTime') is not None:
            kwargs.update({'endTime': int(args.get('endTime'))})
        if args.get('filterPattern') is not None:
            kwargs.update({'filterPattern': args.get('filterPattern')})
        if args.get('limit') is not None:
            kwargs.update({'limit': int(args.get('limit'))})
        if args.get('interleaved') is not None:
            kwargs.update({'interleaved': True if args.get('interleaved') == 'True' else False})

        response = client.filter_log_events(**kwargs)
        for event in response['events']:
            data.append({
                'LogStreamName': event['logStreamName'],
                'Timestamp': event['timestamp'],
                'Message': event['message'],
                'IngestionTime': event['ingestionTime'],
                'EventId': event['eventId']
            })

        ec = {"AWS.CloudWatchLogs.Events(val.eventId === obj.eventId)": data}
        return create_entry('AWS CloudWatch Logs Events', data, ec)

    except Exception as e:
        return raise_error(e)


def describe_log_groups(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        data = []
        kwargs = {}
        if args.get('logGroupNamePrefix') is not None:
            kwargs.update({'logGroupNamePrefix': args.get('logGroupNamePrefix')})
        if args.get('limit') is not None:
            kwargs.update({'limit': int(args.get('limit'))})

        response = client.describe_log_groups(**kwargs)
        for i, logGroup in enumerate(response['logGroups']):
            data.append({
                'LogGroupName': logGroup['logGroupName'],
                'CreationTime': logGroup['creationTime'],
                'Arn': logGroup['arn'],
            })
            if 'retentionInDays' in logGroup:
                data[i].update({'RetentionInDays': logGroup['retentionInDays']})
            if 'metricFilterCount' in logGroup:
                data[i].update({'MetricFilterCount': logGroup['metricFilterCount']})
            if 'storedBytes' in logGroup:
                data[i].update({'StoredBytes': logGroup['storedBytes']})
            if 'kmsKeyId' in logGroup:
                data[i].update({'KmsKeyId': logGroup['kmsKeyId']})

        ec = {"AWS.CloudWatchLogs.LogGroups(val.LogGroupName === obj.LogGroupName)": data}
        return create_entry('AWS CloudWatch Log Groups', data, ec)

    except Exception as e:
        return raise_error(e)


def describe_log_streams(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        data = []
        kwargs = {'logGroupName': args.get('logGroupName')}
        if args.get('logStreamNamePrefix') is not None:
            kwargs.update({'logStreamNamePrefix': args.get('logStreamNamePrefix')})
        if args.get('limit') is not None:
            kwargs.update({'limit': int(args.get('limit'))})
        if args.get('orderBy') is not None:
            kwargs.update({'orderBy': args.get('orderBy')})

        response = client.describe_log_streams(**kwargs)
        for i, logStream in enumerate(response['logStreams']):
            data.append({
                'LogGroupName': args.get('logGroupName'),
                'LogStreamName': logStream['creationTime'],
                'CreationTime': logStream['creationTime'],
                'Arn': logStream['arn'],
            })
            if 'firstEventTimestamp' in logStream:
                data[i].update({'FirstEventTimestamp': logStream['firstEventTimestamp']})
            if 'lastEventTimestamp' in logStream:
                data[i].update({'LastEventTimestamp': logStream['lastEventTimestamp']})
            if 'storedBytes' in logStream:
                data[i].update({'StoredBytes': logStream['storedBytes']})
            if 'lastIngestionTime' in logStream:
                data[i].update({'LastIngestionTime': logStream['lastIngestionTime']})
            if 'uploadSequenceToken' in logStream:
                data[i].update({'UploadSequenceToken': logStream['uploadSequenceToken']})

        ec = {"AWS.CloudWatchLogs.LogGroups(val.LogGroupName === obj.LogGroupName).LogStreams": data}
        return create_entry('AWS CloudWatch Log Streams', data, ec)

    except Exception as e:
        return raise_error(e)


def put_retention_policy(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'retentionInDays': int(args.get('retentionInDays')),
        }
        response = client.put_retention_policy(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Group Retention Policy was added successfully"

    except Exception as e:
        return raise_error(e)


def delete_retention_policy(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        response = client.delete_retention_policy(logGroupName=args.get('logGroupName'))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Log Group Retention Policy was Deleted successfully"

    except Exception as e:
        return raise_error(e)


def put_log_events(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'logStreamName': args.get('logStreamName'),
            'logEvents': [{
                'timestamp': int(args.get('timestamp')),
                'message': args.get('message'),
            }]
        }
        if args.get('sequenceToken') is not None:
            kwargs.update({'sequenceToken': args.get('sequenceToken')})

        response = client.put_log_events(**kwargs)
        data = ({'NextSequenceToken': response['nextSequenceToken']})

        ec = {"AWS.CloudWatchLogs.PutLogEvents": data}
        return create_entry('AWS CloudWatch Log Put Log Events', data, ec)

    except Exception as e:
        return raise_error(e)


def put_metric_filter(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'filterName': args.get('filterName'),
            'filterPattern': args.get('filterPattern'),
            'metricTransformations': [{
                'metricName': args.get('metricName'),
                'metricNamespace': args.get('metricNamespace'),
                'metricValue': args.get('metricValue'),
            }]
        }
        response = client.put_metric_filter(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Metric Filter was added successfully"

    except Exception as e:
        return raise_error(e)


def delete_metric_filter(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        kwargs = {
            'logGroupName': args.get('logGroupName'),
            'filterName': args.get('filterName'),
        }

        response = client.delete_metric_filter(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "The Metric Filter was Deleted successfully"

    except Exception as e:
        return raise_error(e)


def describe_metric_filters(args, aws_client):
    try:
        client = aws_client.aws_session(
            service='logs',
            region=args.get('region'),
            role_arn=args.get('roleArn'),
            role_session_name=args.get('roleSessionName'),
            role_session_duration=args.get('roleSessionDuration'),
        )
        data = []
        kwargs = {}
        if args.get('logGroupName') is not None:
            kwargs.update({'logGroupName': args.get('logGroupName')})
        if args.get('filterNamePrefix') is not None:
            kwargs.update({'filterNamePrefix': args.get('filterNamePrefix')})
        if args.get('metricName') is not None:
            kwargs.update({'metricName': args.get('metricName')})
        if args.get('metricNamespace') is not None:
            kwargs.update({'metricNamespace': args.get('metricNamespace')})

        response = client.describe_metric_filters(**kwargs)
        for metric in response['metricFilters']:
            data.append({
                'FilterName': metric['filterName'],
                'FilterPattern': metric['filterPattern'],
                'CreationTime': metric['creationTime'],
                'LogGroupName': metric['logGroupName']
            })

        raw = json.loads(json.dumps(response['metricFilters'], cls=DatetimeEncoder))
        ec = {"AWS.CloudWatchLogs.MetricFilters(val.FilterName === obj.FilterName)": raw}
        return create_entry('AWS CloudWatch Metric Filters', data, ec)

    except Exception as e:
        return raise_error(e)


def fetch_incidents(aws_client, log_group_name: str, log_stream_names: List[str], first_fetch: str,
                    filter_pattern: str = '', max_fetch: int = 0):
    demisto.debug(f'Fetching incidents with params log_group_name: {log_group_name}, '
                  f'log_stream_names: {log_stream_names}, first_fetch: {first_fetch}, filter_pattern: {filter_pattern}, max_fetch: {max_fetch}')
    client = aws_client.aws_session(service='logs')

    last_run = demisto.getLastRun()
    if last_run and last_run.get('last_fetch'):
        start_time = last_run.get('last_fetch')
    else:
        start_time = first_fetch.timestamp() * 1000

    incidents = []
    kwargs = {
        'logGroupName': log_group_name,
        'startTime': int(start_time),
        'filterPattern': filter_pattern,
        'interleaved': False
    }

    if log_stream_names:
        kwargs.update({'logStreamNames': parse_resource_ids(','.join(log_stream_names))})

    if max_fetch:
        kwargs.update({'max_fetch': max_fetch})

    demisto.debug(f'Running fetch with {json.dumps(kwargs)}')
    response = client.filter_log_events(**kwargs)
    demisto.debug(f'Received response {json.dumps(response)}')

    last_fetch = start_time
    for event in response['events']:
        event_time = event['timestamp']
        if type(event_time) is str and event_time.isnumeric():
            event_time = int(event_time)
        
        if type(event_time) is int and event_time > last_fetch:
            last_fetch = event_time

        try:
            event['message'] = json.loads(event['message'])
        except json.decoder.JSONDecodeError:
            demisto.debug(f'Could not parse message `{event["message"]}` as JSON')

        incidents.append({
            'name': f'AWS CloudWatch Logs {log_group_name}',
            'occurred': timestamp_to_datestring(event_time),
            'rawJSON': json.dumps(event)
        })

    if len(incidents) > 0:
        # If we keep last_fetch equal to the last event's time, we will 
        # continue to pull the same event on the next fetch.
        last_run['last_fetch'] = last_fetch + 1
    else:
        last_run['last_fetch'] = last_fetch
    demisto.debug(f'Setting last run to {json.dumps(last_run)}')
    demisto.debug(f'Returning {len(incidents)} incidents')
    demisto.incidents(incidents)
    demisto.setLastRun(last_run)



def test_function(aws_client):
    try:
        client = aws_client.aws_session(service='logs')
        response = client.describe_log_groups()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'ok'

    except Exception as error:
        return error


def main():

    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('credentials', {}).get('identifier') or params.get('access_key')
    aws_secret_access_key = params.get('credentials', {}).get('password') or params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5

    validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                    aws_secret_access_key)

    aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                           aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                           retries)
    command = demisto.command()
    args = demisto.args()

    if command == 'test-module':
        # This is the call made when pressing the integration test button.
        result = test_function(aws_client)

    if command == 'fetch-incidents':
        log_group_name = params.get('log_group_name', '')
        log_stream_names = params.get('log_stream_names', '')
        filter_pattern = params.get('filter_pattern', '')
        max_fetch = arg_to_number(params.get('max_fetch', 50))
        first_fetch = arg_to_datetime(
            arg=params['first_fetch'], arg_name='First fetch time', required=True
        )
        fetch_incidents(aws_client,
                        log_group_name,
                        log_stream_names,
                        first_fetch,
                        filter_pattern,
                        max_fetch)
        return

    if command == 'aws-logs-create-log-group':
        result = create_log_group(args, aws_client)

    if command == 'aws-logs-create-log-stream':
        result = create_log_stream(args, aws_client)

    if command == 'aws-logs-delete-log-group':
        result = delete_log_group(args, aws_client)

    if command == 'aws-logs-delete-log-stream':
        result = delete_log_stream(args, aws_client)

    if command == 'aws-logs-filter-log-events':
        result = filter_log_events(args, aws_client)

    if command == 'aws-logs-describe-log-groups':
        result = describe_log_groups(args, aws_client)

    if command == 'aws-logs-describe-log-streams':
        result = describe_log_streams(args, aws_client)

    if command == 'aws-logs-put-retention-policy':
        result = put_retention_policy(args, aws_client)

    if command == 'aws-logs-delete-retention-policy':
        result = delete_retention_policy(args, aws_client)

    if command == 'aws-logs-put-log-events':
        result = put_log_events(args, aws_client)

    if command == 'aws-logs-put-metric-filter':
        result = put_metric_filter(args, aws_client)

    if command == 'aws-logs-delete-metric-filter':
        result = delete_metric_filter(args, aws_client)

    if command == 'aws-logs-describe-metric-filters':
        result = describe_metric_filters(args, aws_client)

    demisto.results(result)


from AWSApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

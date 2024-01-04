import logging
import json
import boto3
import botocore
from jinja2 import Template


def get_sse_config(s3_client, s3_response) -> None:
    """Get S3 SSE Configuration"""
    print("\nSetting S3 SSE Configuration\n")
    s3_sse_policy = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    try:
        for bucket in s3_response['Buckets']:
            get_encryption = s3_client.get_bucket_encryption(Bucket=bucket["Name"])
            sse_enabled = (get_encryption['ServerSideEncryptionConfiguration']['Rules'][0]
                ['ApplyServerSideEncryptionByDefault'])
            if sse_enabled:
                logging.warning("SSE Enabled\n\t%s %s", bucket['Name'], sse_enabled)
            else:
                logging.info("Enabling SSE for S3 Bucket: %s", bucket['Name'])
                s3_client.put_bucket_encryption(Bucket=bucket["Name"],
                    ServerSideEncryptionConfiguration=s3_sse_policy)
                logging.info("%s %s", s3_sse_policy, bucket['Name'])
    except botocore.exceptions.ClientError as error:
        logging.error(error)
        raise error


def get_secure_transport(s3_client, s3_response) -> None:
    """Get Secure Transport"""
    print("\nChecking SecureTransport\n")
    with open("sec_trans.json", "r", encoding="UTF-8") as file_a, \
            open("sec_trans_append.json", "r", encoding="UTF-8") as file_b:
        sectrans_template = Template(file_a.read())
        sectrans_template_append = Template(file_b.read())
    try:
        for bucket in s3_response['Buckets']:
            sec_trans = s3_client.get_bucket_policy(Bucket=bucket['Name'])
            current_pol = json.loads(sec_trans['Policy'])
            if current_pol['Statement']:
                for statement in current_pol['Statement']:
                    if ('Condition' not in statement) or ('Bool' not in statement['Condition']):
                        logging.info("%s: POLICY FOUND, ENABLING Secure Transport", bucket['Name'])
                        logging.info("%s\n", current_pol)
                        add_pol = json.loads(sectrans_template_append.render(
                                    bucket_name=bucket['Name']))
                        current_pol['Statement'].append(add_pol)
                        new_pol = json.dumps(current_pol)
                        logging.info("%s\n", new_pol)
                        sectrans_response = s3_client.put_bucket_policy(Bucket=bucket['Name'],
                                                Policy=new_pol)
                    elif statement['Condition']['Bool']['aws:SecureTransport'] == 'false':
                        logging.warning("%s: SECURE TRANSPORT ALREADY ENABLED, Current Policy:\
                            \n\t %s", bucket['Name'], current_pol)
    except botocore.exceptions.ClientError as error:
        logging.warning(error)
        logging.warning("%s: NO POLICY FOUND, Attaching one now", bucket['Name'])
        sectrans_policy = sectrans_template.render(bucket_name=bucket['Name'])
        logging.warning("%s", sectrans_policy)
        sectrans_response = s3_client.put_bucket_policy(Bucket=bucket['Name'],
                                Policy=sectrans_policy)
        logging.warning(sectrans_response)


def main() -> None:
    """Main function"""
    s3_client = boto3.client('s3')
    s3_response = s3_client.list_buckets()
    get_sse_config(s3_client, s3_response)
    get_secure_transport(s3_client, s3_response)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    main()

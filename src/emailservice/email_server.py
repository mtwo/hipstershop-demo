from concurrent import futures
import os
import time

from jinja2 import Environment, FileSystemLoader, select_autoescape, TemplateError
from google.api_core.exceptions import GoogleAPICallError
from google.cloud.mail import CloudMailClient
import grpc

import ms_demo_mail_service_pb2
import ms_demo_mail_service_pb2_grpc

# Loads confirmation email template from file
env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml'])
)
template = env.get_template('confirmation.html')

# Creates a Cloud Mail client
client = CloudMailClient()

project_id = os.environ["GCLOUD_PROJECT"]
region = 'us-central1'
sender_id ='default-sender'
from_address = os.environ["CLOUD_MAIL_FROM_ADDRESS"]

class EmailService(ms_demo_mail_service_pb2_grpc.EmailServiceServicer):
  @staticmethod
  def send_email(email_address, content):
    client = CloudMailClient()

    response = client.send_message(
      sender = client.sender_path(project_id, region, sender_id),
      envelope_from_authority = '',
      header_from_authority = '',
      envelope_from_address = from_address,
      simple_message = {
        "from": {
          "address_spec": from_address,
        },
        "to": [{ 
          "address_spec": email_address 
        }],
        "subject": "Your Confirmation Email",
        "html_body": content
      }
    )
    
    print("Message sent: {}".format(response.rfc822_message_id))

  def SendOrderConfirmation(self, request, context):
    email = request.email
    order = request.order

    try:
      confirmation = template.render(order = order)
    except TemplateError:
      context.set_details("An error occurred when preparing the confirmation page.")
      context.set_code(grpc.StatusCode.INTERNAL)
      return ms_demo_mail_service_pb2.Empty()

    try:
      EmailService.send_email(email, order)
    except GoogleAPICallError:
      context.set_details("An error occurred when preparing the confirmation page.")
      context.set_code(grpc.StatusCode.INTERNAL)
      return ms_demo_mail_service_pb2.Empty()

    return ms_demo_mail_service_pb2.Empty()

def start():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    ms_demo_mail_service_pb2_grpc.add_EmailServiceServicer_to_server(EmailService(), server)
    server.add_insecure_port('[::]:5000')
    server.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == '__main__':
    start()
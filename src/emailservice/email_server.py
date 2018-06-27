from concurrent import futures
import argparse
import os
import sys
import time

from jinja2 import Environment, FileSystemLoader, select_autoescape, TemplateError
from google.api_core.exceptions import GoogleAPICallError
from google.cloud.mail import CloudMailClient
import grpc

import demo_pb2
import demo_pb2_grpc

# Loads confirmation email template from file
env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml'])
)
template = env.get_template('confirmation.html')

class EmailService(demo_pb2_grpc.EmailServiceServicer):
  def __init__(self):
    self.client = CloudMailClient()
    super().__init__()

  @staticmethod
  def send_email(client, email_address, content):
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
    except TemplateError as err:
      context.set_details("An error occurred when preparing the confirmation page.")
      print(err.message)
      context.set_code(grpc.StatusCode.INTERNAL)
      return demo_pb2.Empty()

    try:
      EmailService.send_email(self.client, email, confirmation)
    except GoogleAPICallError as err:
      context.set_details("An error occurred when sending the email.")
      print(err.message)
      context.set_code(grpc.StatusCode.INTERNAL)
      return demo_pb2.Empty()

    return demo_pb2.Empty()

class DummyEmailService(demo_pb2_grpc.EmailServiceServicer):
  def SendOrderConfirmation(self, request, context):
    print('A request to send order confirmation email to {} has been received.'.format(request.email))

    return demo_pb2.Empty()

def start(dummy_mode):
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
  if dummy_mode:
    demo_pb2_grpc.add_EmailServiceServicer_to_server(DummyEmailService(), server)
  else:
    demo_pb2_grpc.add_EmailServiceServicer_to_server(EmailService(), server)
  server.add_insecure_port('[::]:8080')
  server.start()
  try:
    while True:
      time.sleep(3600)
  except KeyboardInterrupt:
    server.stop(0)


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('-m', '--mail', help='run the email service with Cloud Mail integration', action="store_true")
  parser.add_argument('-p', '--project', help='your google cloud project id')
  parser.add_argument('-a', '--address', help='envelope from address Cloud Mail uses to send email')
  parser.add_argument('-s', '--sender', help='the id of your Cloud Mail sender')
  parser.add_argument('-r', '--region', help='the region of your Cloud Mail resources')
  args = parser.parse_args()
  if not args.mail:
    print('Starting the email service in dummy mode.')
    start(dummy_mode = True)
  else:
    print('Starting the email service with Cloud Mail integration.')
    if args.project == None:
      print('Error: Google Cloud Project ID is missing. See the README file for more information.')
      sys.exit(1)
    if args.address == None:
      print('Error: Envelope from address is missing. See the README file for more information.')
      sys.exit(1)
    if args.sender == None:
      print('Error: Sender ID is missing. See the README file for more information.')
      sys.exit(1)
    if args.region == None:
      print('Error: Cloud Mail region setting is missing. See the README file for more information.')
      sys.exit(1)
    project_id = args.project
    from_address = args.address
    sender_id = args.sender
    region = args.region
    start(dummy_mode = False)

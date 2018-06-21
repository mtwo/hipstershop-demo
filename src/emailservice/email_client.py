import grpc

import demo_pb2
import demo_pb2_grpc

def send_confirmation_email(email, order):
  channel = grpc.insecure_channel('0.0.0.0:8080')
  stub = demo_pb2_grpc.EmailServiceStub(channel)
  try:
    response = stub.SendOrderConfirmation(demo_pb2.SendOrderConfirmationRequest(
      email = email,
      order = order
    ))
    print('Request sent.')
  except grpc.RpcError as err:
    print(err.details())
    print('{}, {}'.format(err.code().name, err.code().value))

if __name__ == '__main__':
  print('Client for email service.')
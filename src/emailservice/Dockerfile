# Use the grpc.io provided Python image as the base image
FROM grpc/python:1.0

RUN apt-get update && apt-get install python3-pip -y

# Add the application
ADD email_server /email_server/

# Add Google Cloud Mail client library for Python
# Google Cloud Mail is currently in Alpha. Client libraries provided for
# Google Cloud Mail Alpha are shipped separately from standard
# Google Cloud client libraries and are provided only for early adopters'
# convenience. Features may change in backward-incompatible ways and are not
# recommended for production use. It is not subject to any SLA or deprecation
# policy.
# See https://cloud.google.com/mail/docs for more information
ADD cloudmail-v1alpha3 /cloudmail-v1alpha3/

# Install required packages
RUN python3 -m pip install --upgrade -r /email_server/requirements.txt
RUN python3 -m pip install -e cloudmail-v1alpha3/

EXPOSE 8080

WORKDIR /email_server
ENTRYPOINT [ "python3", "email_server.py" ]

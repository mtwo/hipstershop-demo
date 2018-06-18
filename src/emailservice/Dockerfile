# Use the Google Cloud Platform provided Debian 9 Docker (Stretch) image
# as the base image
FROM gcr.io/google-appengine/debian9

# Install updates and dependencies
RUN apt-get update -y && \
	apt-get install --no-install-recommends -y -q \
        python \
        python3 && \
    apt-get clean

# Add the application
ADD email_server.py /email_server
ADD ms_demo_mail_service_pb2_grpc.py /email_server
ADD ms_demo_mail_service_pb2.py /mail_server
ADD requirements.txt .
ADD templates /email_server/templates

# Add Google Cloud Mail client library for Python
# Google Cloud Mail is currently in Alpha. Client libraries provided for
# Google Cloud Mail Alpha are shipped separately from standard
# Google Cloud client libraries and are provided only for early adopters'
# convenience. Features may change in backward-incompatible ways and are not
# recommended for production use. It is not subject to any SLA or deprecation
# policy.
# See https://cloud.google.com/mail/docs for more information
ADD cloud_mail_v1alpha3_python/ ./cloud_mail_v1alpha3_python

# Install required packages
RUN pip install --upgrade -r requirements.txt

# Install Google Cloud Mail client library for Python
RUN pip install -e cloud_mail_v1alpha3_python/

# Set up environment variables
ENV GOOGLE_APPLICATION_CREDENTIALS="/path/to/JSON/keyfile"
ENV GCLOUD_PROJECT="YOUR-PROJECT-NAME"
ENV CLOUD_MAIL_FROM_ADDRESS="YOUR-FROM-ADDRESS"

CMD gunicorn -w 10 /email_server/email_server.py

# Email Service for Cloud Next 2018 Microservices Demo

This email service sends a confirmation email when an order is completed. It
features two different mode:

* Dummy mode: accepts requests but does not send any message; instead, write a log entry to stdout
* Cloud Mail mode: accepts requests and send messages via [Google Cloud Mail](https://cloud.google.com/mail).

## Building the image

Run command:

    `docker build -f Dockerfile .`

to build the image.

## Running the service locally

### Dummy mode

To start up the service in dummy mode, run command

    `docker run -it -p 8080:8080 [YOUR-IMAGE-ID]`

You should see a message, `Starting the email service in dummy mode.` in the output.

Call method `send_confirmation_email` in `email_client.py`; pass an email address
and an order as parameters. Refer to the proto file for
the format of the order message. A log entry should show up in the output of the
service.

### Cloud Mail mode

Refer to the [Google Cloud Mail documentation](https://cloud.google.com/mail/docs) to get started.
After setting up Cloud Mail, mount a volume with your service account JSON key file in it,
create environment variable `GOOGLE_APPLICATION_CREDENTIALS`
with the path to the key file and start the
service with the volume:

    ```
    docker run -it -p 8080:8080 ---mount [MOUNT-SOURCE-AND-TARGET]  \
    [IMAGE-ID]
    -m
    -p [GOOGLE_CLOUD_PROJECT]
    -a [ENVELOPE_FROM_ADDRESS]
    -s [CLOUD-MAIL-SENDER-ID]
    -r [CLOUD-MAIL-REGION]
    ```

You should see a message, `Starting the email service with Cloud Mail integration.` in the output.

Call method `send_confirmation_email` in `email_client.py`; pass an email address
and an order as parameters. Refer to the proto file for
the format of the order message. A message id should show up in the output of the
service.

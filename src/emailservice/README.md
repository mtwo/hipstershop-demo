# Email Service for Cloud Next 2018 Microservices Demo

This email service sends a confirmation email when an order is completed.

## Build

This service uses Google Cloud Mail for sending emails. Google Cloud Mail is
currently in Alpha release; see https://cloud.google.com/mail/docs for
instructions on getting started. 

More specifically:

* Enable Google Cloud Mail API.
* Set up a service account authorized to access Google Cloud Mail. Download the JSON keyfile.
* Create and verify a domain or an email address in Google Cloud Mail.
* Create a sender.
* Modify the dockerfile. Set the following environment variables:

```
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/JSON/keyfile"
export GCLOUD_PROJECT="YOUR-PROJECT-NAME"
export CLOUD_MAIL_FROM_ADDRESS="YOUR-FROM-ADDRESS"
```


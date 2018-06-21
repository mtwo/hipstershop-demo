# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Wrappers for protocol buffer enum types."""

import enum


class ReceiptRule(object):
    class Pattern(object):
        class MatchMode(enum.IntEnum):
            """
            All MatchModes are applied to the local part of a canonicalized address
            (lower-cased, 5321 quoted-string removed)
            The \"local part\" is the part of the email address before the @.

            Attributes:
              MATCH_MODE_UNSPECIFIED (int): Unspecified MatchMode.
              EXACT (int): An exact string match against the local part of the canonicalized
              address.
              PREFIX (int): A prefix string match against the local part of the canonicalized
              address.
              REGEXP (int): An RE2-compatible regular expression to match against the local part
              of the canonicalized address.
            """
            MATCH_MODE_UNSPECIFIED = 0
            EXACT = 1
            PREFIX = 2
            REGEXP = 3


class DeliverAction(object):
    class Mode(enum.IntEnum):
        """
        Mode defines when a message is delivered to StoreAction and/or
        included in the push_method.

        Attributes:
          MODE_UNSPECIFIED (int): Unspecified Mode.
          STORE_ALL (int): store all messages, do not post any raw inline. StoreAction
          must be provided.
          POST_SMALL_INLINE (int): store all messages, post small raw inline. StoreAction and
          push_method must be provided.
          STORE_LARGE (int): store only messages too large to post inline. push_method must
          be provided. If StoreAction is not provided, large messages
          will be rejected.
        """
        MODE_UNSPECIFIED = 0
        STORE_ALL = 1
        POST_SMALL_INLINE = 2
        STORE_LARGE = 3


class Domain(object):
    class Status(enum.IntEnum):
        """
        Status of the domain for usage with the Cloud Mail service.

        Attributes:
          STATUS_UNSPECIFIED (int): Unspecified status.
          ACTIVE (int): Domain is verified and active for use.
          NOT_VERIFIED (int): Domain is not verified.
          VERIFICATION_LAPSED (int): Domain was previously verified but the verification records are no longer
          extant.
          PREEMPTED (int): Domain was previously verified but has since been registered and verified
          for use in another Domain resource.
        """
        STATUS_UNSPECIFIED = 0
        ACTIVE = 1
        NOT_VERIFIED = 2
        VERIFICATION_LAPSED = 3
        PREEMPTED = 4

    class DnsAliasStatus(enum.IntEnum):
        """
        Status of customer dns records that point to cloudmail.

        Attributes:
          DNS_ALIAS_STATUS_UNSPECIFIED (int): Unspecified status.
          DNS_ALIAS_STATUS_INVALID (int): mx record does not exist or does not point to cloudmail
          DNS_ALIAS_STATUS_VALID (int): mx record points to cloudmail
        """
        DNS_ALIAS_STATUS_UNSPECIFIED = 0
        DNS_ALIAS_STATUS_INVALID = 1
        DNS_ALIAS_STATUS_VALID = 2


class EmailVerifiedAddress(object):
    class Status(enum.IntEnum):
        """
        Possible values for verification status of this address.

        Attributes:
          STATUS_UNSPECIFIED (int): Unspecified status.
          NOT_VERIFIED (int): The address has not yet been verified.
          VERIFICATION_LAPSED (int): The address was previously verified, but verification has been cancelled
          or expired.
          VERIFIED (int): The address is currently verified.
        """
        STATUS_UNSPECIFIED = 0
        NOT_VERIFIED = 1
        VERIFICATION_LAPSED = 2
        VERIFIED = 3

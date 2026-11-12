---
name: acme_access_review
title: Review a user's access
description: Read-only review of what a user can reach, for the quarterly access review.
arguments:
  - name: username
    description: Whose access to review
    required: true
  - name: reviewer
    description: Who asked for the review, for the report
tools: [keycloak_acme_user_summary, keycloak_user_roles_get, keycloak_user_groups_list]
---
Review the access of the user {{username}}. Read only; change nothing.

1. Show the user summary and confirm it is the right person.
2. Read the user's roles with their sources: which are direct, which come from a group or a composite role.
3. List the user's groups.
4. Report: the roles that give administrative access, each with its source, and anything that looks left over,
   such as a direct role that a group already grants.
{{#reviewer}}
5. Address the report to {{reviewer}}.
{{/reviewer}}

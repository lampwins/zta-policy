# ZTA Policy

This repo contains PhD research work related to a policy language for zero trust network security.

## Policy

`policy.json` contains a set of policies using the policy language grammar, but expressed as JSON objects for simplicity.
In this example system, `policy.json` is the input which represents the network administrator's policy intent.

## Applications

A major feature of the policy language is the ability to add additional dynamic context. In this example system, we define a registry of applications in `apps.json` which can be referenced by a policy. In a more realistic scenario, the policy engine would provide this context via hooks into other systems.

## Compiler

The compiler is a very simple tool which takes the `policy.json` and `apps.json` as input, and renders out the policy into domain specific policy languages.

There is currently support for iptables and palo alto networks policy syntax.

Ransomware Resilience: Hardening Azure Workloads End to End

Lab Overview
• Cloud: Azure
• Duration: 180 minutes
• Exercises: 6 (Challenge 1 — Establish resilient backup governance: 25 minutes; Challenge 2 — Harden Container B and the VM against tampering: 25 minutes; Challenge 3 — Prove the authorization boundary holds: 20 minutes; Challenge 4 — Attack Container B and prove protection blocked tampering: 30 minutes; Challenge 5 — Investigate the ransomware signal and rotate access: 25 minutes; Challenge 6 — Restore the VM, validate integrity, and produce a recovery runbook: 55 minutes including restore wait. Total: 180 minutes.)
• Validations: 4
• Deployed services: Azure Virtual Machine, Virtual Network, Network Security Group, Public IP address, Network Interface, Storage Account with Blob containers containera-unprotected, containerb-protectme, and lab-evidence, Recovery Services vault with VM backup protected item, Resource Guard for selected Azure Backup MUA-protected operations, Log Analytics workspace, Azure Monitor diagnostic settings at the Blob service scope, Microsoft.Security/defenderForStorageSettings/current at API version 2025-01-01, Custom RBAC role definition, Azure Policy definition
• Scenario: Learners operate a ransomware-resilience sandbox containing one Azure VM recovery target and one storage account with two identically seeded target containers: Container A is attacked automatically during deployment and remains intentionally unprotected, while Container B is hardened by the learner before the same benign encryption-mimic script is run against it. The environment supplies exactly one Microsoft Entra learner identity; trainerUserName and trainerUserPassword are local VM Shadow credentials for VM access support only and are not an Entra approver. Challenge 3 captures a protected-operation authorization failure and a written conceptual explanation of the full Resource Guard-backed MUA flow; requester/approver identities are not supplied, no approver inject/output is assumed, and approval is not performed.

Provisioning Accuracy Note
• The ARM/platform deployment identity creates the Resource Guard and Microsoft.RecoveryServices/vaults/backupResourceGuardProxies mapping. The Custom Script Extension verifies the vault-to-Resource Guard mapping read-only. The candidate role has Resource Guard read/discovery permissions only and no Resource Guard write permission; any coherence warning expecting candidate Resource Guard write is a checker false positive because it assumes the candidate role deploys every ARM resource.

This Package Includes

Deliverables Included in the Package
• Lab Guide
• Master Document
• Inline Validations

Inline Validations
Pre-configured inline validations enabled

Lab Guide Preview
Preview link for the lab guide documentation:
[\[CloudLabs LabGuide Preview\]](https://experience.cloudlabs.ai/#labguidepreview/<GUID>/1)

Lab Environment Setup & Deployment
Lab provisioning and setup include one or more of the following components:
• ARM template deployment
• Custom Script Extension (CSE)
• Custom image-based environment setup
• Supporting deployment configurations as required

Exclusions
This package does not include:
• Scoring or grading mechanisms for inline validations
• Complex or advanced inline question types
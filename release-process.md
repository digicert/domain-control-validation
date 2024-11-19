# Release Process (Work in Progress)

This document outlines the steps required to release a new version of the project. The process includes both automated steps, executed via GitHub Actions, and manual steps that require human intervention.

## Table of Contents

1. [Initial Setup for Maven Publishing](#initial-setup-for-maven-publishing)
2. [Automated Deployment Process](#automated-deployment-process)
3. [Manual Steps After Deployment](#manual-steps-after-deployment)
4. [Rationale for Manual Steps](#rationale-for-manual-steps)
5. [Example Commands](#example-commands)

---

## Initial Setup for Maven Publishing

*To be completed.*

---

## Automated Deployment Process

The deployment process is automated using a `release.yml` GitHub Actions workflow. This workflow is triggered when a new tag is pushed to the `master` branch.

### Process Overview:

- **User Action**: Creates a new tag (e.g., `v1.0.0-beta1`).
- **Workflow Trigger**: GitHub Actions listens for new tags on the `master` branch.
- **Workflow Steps**:
  1. **Checkout Code for New Tag**
  2. **Set New Version in Repository**
  3. **Commit and Push Changes to Release Branch**
  4. **Create GitHub Release Based on Tag**
  5. **Deploy Artifacts**:
     - Deploy to Internal Nexus
     - Deploy to Maven Central

### Detailed Steps:

1. **Tagging a Release**

   - **Action**: A user creates a new tag in the repository, e.g., `v1.0.0-beta1`.
   - **Command**:

     ```sh
     git tag -a v1.0.0-beta1 -m "Version 1.0.0-beta1"
     git push origin v1.0.0-beta1
     ```

   - **Note**: The tag should follow [Semantic Versioning](https://semver.org/) conventions.

2. **Workflow Trigger**

   - **Action**: The GitHub Actions workflow listens for new tags on the `master` branch.
   - **Configuration**:

     ```yaml
     on:
       push:
         tags:
           - 'v*'
         branches:
           - master
     ```

   - **Outcome**: When a new tag matching the pattern is detected, the workflow is triggered.

3. **Checkout Code for New Tag**

   - **Action**: The workflow checks out the code corresponding to the new tag.
   - **Uses**: `actions/checkout@v3` action.
   - **Step**:

     ```yaml
     - name: Checkout Code
       uses: actions/checkout@v3
       with:
         ref: ${{ github.ref }}
     ```

4. **Set New Version in Repository**

   - **Action**: Update the project version using Maven.
   - **Command**:

     ```sh
     mvn versions:set -DnewVersion=${GITHUB_REF_NAME}
     ```

   - **Workflow Step**:

     ```yaml
     - name: Set Project Version
       run: mvn versions:set -DnewVersion=${GITHUB_REF_NAME}
     ```

5. **Commit and Push Changes to Release Branch**

   - **Action**: Commit the version changes and push to a new release branch.
   - **Commands**:

     ```sh
     git checkout -b release/${GITHUB_REF_NAME}
     git add pom.xml
     git commit -m "Set version to ${GITHUB_REF_NAME}"
     git push origin release/${GITHUB_REF_NAME}
     ```

   - **Workflow Steps**:

     ```yaml
     - name: Commit Version Changes
       run: |
         git config user.name "${{ github.actor }}"
         git config user.email "${{ github.actor }}@users.noreply.github.com"
         git checkout -b release/${GITHUB_REF_NAME}
         git add pom.xml
         git commit -m "Set version to ${GITHUB_REF_NAME}"
         git push origin release/${GITHUB_REF_NAME}
     ```

6. **Create GitHub Release Based on Tag**

   - **Action**: Create a new GitHub release using the tag.
   - **Uses**: `actions/create-release@v1` action.
   - **Workflow Step**:

     ```yaml
     - name: Create Release
       uses: actions/create-release@v1
       with:
         tag_name: ${{ github.ref_name }}
         release_name: Release ${{ github.ref_name }}
         body: |
           ## What's New
           - Describe the changes here.
         draft: false
         prerelease: ${{ contains(github.ref_name, '-beta') }}
       env:
         GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
     ```

7. **Deploy Artifacts**

   - **Deploy to Internal Nexus**

     - **Command**:

       ```sh
       mvn clean deploy -P release -DaltDeploymentRepository=nexus::default::http://your-internal-nexus/repository
       ```

     - **Workflow Step**:

       ```yaml
       - name: Deploy to Internal Nexus
         run: mvn clean deploy -P release -DaltDeploymentRepository=nexus::default::http://your-internal-nexus/repository
         env:
           NEXUS_USERNAME: ${{ secrets.NEXUS_USERNAME }}
           NEXUS_PASSWORD: ${{ secrets.NEXUS_PASSWORD }}
       ```

   - **Deploy to Maven Central**

     - **Condition**: Only if the tag does not contain `-beta`.
     - **Command**:

       ```sh
       mvn clean deploy -P release
       ```

     - **Workflow Step**:

       ```yaml
       - name: Deploy to Maven Central
         if: ${{ !contains(github.ref_name, '-beta') }}
         run: mvn clean deploy -P release
         env:
           SONATYPE_USERNAME: ${{ secrets.SONATYPE_USERNAME }}
           SONATYPE_PASSWORD: ${{ secrets.SONATYPE_PASSWORD }}
       ```

   - **Credentials**:
     - Provided via GitHub secrets:
       - `NEXUS_USERNAME`
       - `NEXUS_PASSWORD`
       - `SONATYPE_USERNAME`
       - `SONATYPE_PASSWORD`

---

## Manual Steps After Deployment

While the automated process handles most of the deployment tasks, some steps require manual intervention to ensure accuracy and compliance.

1. **Publish PGP Key**

   - **Action**: Ensure your PGP key is published on [OpenPGP Key Server](https://keys.openpgp.org/).
   - **Reason**: Required for signing artifacts and verifying authenticity.

2. **Push Remaining Changes**

   - **Action**: Push any remaining changes to the repository, if necessary.

3. **Finalize the Release on GitHub**

   - **Action**: If the release was not automatically created, manually create it on GitHub.
   - **Details**: Include release notes, changelog, and any relevant information.

4. **Announce the New Release**

   - **Action**: Make announcements about the new release.
   - **Channels**: Email lists, social media, project website, etc.

5. **Update Documentation**

   - **Action**: Update all documentation to reflect the new version.
   - **Steps**:
     - Perform a global search and replace to update the version number:

       ```sh
       find . -name "*.md" -exec sed -i 's/old_version/new_version/g' {} +
       ```

     - Upload any new schemas or assets to the project pages.
     - Update the Getting Started guide and examples.

---

## Rationale for Manual Steps

While automation increases efficiency, certain tasks benefit from manual oversight to maintain quality and compliance.

- **PGP Key Verification**

  - Ensuring the PGP key is correctly published and accessible is crucial for security.

- **Documentation Updates**

  - Manual review ensures that the documentation accurately reflects the changes and is free of errors.

- **Release Announcements**

  - Crafting personalized announcements helps engage the community and stakeholders effectively.

---

## Example Commands

Here are some example commands to assist with the release process:

### Tagging a New Release

```sh
# For a beta release
git tag -a v1.0.0-beta1 -m "Version 1.0.0-beta1"
git push origin v1.0.0-beta1

# For a stable release
git tag -a v1.0.0 -m "Version 1.0.0"
git push origin v1.0.0
```

```sh
# Set the project version to match the tag
mvn versions:set -DnewVersion=1.0.0-beta1
# Deploy to Internal Nexus (for beta releases)
mvn clean deploy -P release -DaltDeploymentRepository=nexus::default::http://your-internal-nexus/repository

# Deploy to Maven Central (for stable releases)
mvn clean deploy -P release
```
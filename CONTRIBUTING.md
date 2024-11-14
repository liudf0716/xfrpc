# Contributing to xfrpc

Thank you for considering contributing to [xfrpc](https://github.com/liudf0716/xfrpc)! Please follow these steps to submit your contributions:

## Steps to Contribute:

1. **Fork the Repository**  
   Click the "Fork" button on the top right of the repository page to create a copy of the repository in your GitHub account.

2. **Clone Your Forked Repository**  
   Clone the repository to your local machine using the following command:
   - **Using HTTPS** (recommended for users who haven't set up SSH keys):
     ```bash
     git clone https://github.com/your_github_username/xfrpc.git
     ```
   - **Using SSH** (for users who have set up SSH keys with GitHub):
     ```bash
     git clone git@github.com:your_github_username/xfrpc.git
     ```

3. **Create a New Branch**  
   Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b "your-feature-name"
   ```

4. **Make Changes and Test**  
   Implement your changes locally and test them thoroughly to ensure they work as expected.

5. **Update `contributors.md`**  
   Add your name to the `contributors.md` file.

6. **Commit and Push Your Changes**  
   Commit your changes with a sign-off and push them to your forked repository:
   ```bash
   git commit --signoff
   git push origin your-feature-name
   ```

7. **Create a Pull Request**  
   Open a Pull Request (PR) from your forked repository to the main repository on GitHub and wait for the review process.

## Important Notes:

- **Sync with the Main Repository**: Keep your fork up to date by syncing it regularly with the upstream repository.
  ```bash
  git fetch upstream
  git rebase upstream/master
  ```

- **Resolve Merge Conflicts**: If conflicts arise during rebase or merging, resolve them before submitting the PR.

Thank you for contributing!
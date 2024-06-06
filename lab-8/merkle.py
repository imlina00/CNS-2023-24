import argparse
import binascii
import hashlib
import os
import time
import zlib


class GitRepository:
    def __init__(self, path=".my_git", debug=False):
        self.path = path
        self.debug = debug
        self.objects_dir = os.path.join(self.path, "objects")

    def init(self):
        """Initializes new repo"""
        if not os.path.exists(self.path):
            os.makedirs(self.objects_dir)

    def store_object(self, obj_type, content):
        """Hashes and stores arbitrary git object"""
        full_content = None
        if isinstance(content, str):
            full_content = f"{obj_type}\x20{len(content)}\x00{content}".encode()
        else:
            full_content = f"{obj_type}\x20{len(content)}\x00".encode() + content

        obj_hash_binary = hashlib.sha1(full_content)
        obj_hash = obj_hash_binary.hexdigest()
        obj_dir = os.path.join(self.objects_dir, obj_hash[:2])
        obj_path = os.path.join(obj_dir, obj_hash[2:])

        if self.debug:
            print(f"\nObject path: {obj_path}")
            print(f"Object content:\n{full_content}")
            print(f"Object hash (bytes): {obj_hash_binary.digest()}")

        if not os.path.exists(obj_path):
            os.makedirs(obj_dir, exist_ok=True)
            compressed_content = zlib.compress(full_content)
            with open(obj_path, "wb") as obj_file:
                obj_file.write(compressed_content)
        return obj_hash

    def create_blob(self, filename):
        """Handles git blobs (i.e., files)"""
        with open(filename, "rb") as afile:
            content = afile.read()
        return self.store_object("blob", content)

    def create_tree(self, file_hashes, processed_dirs=set()):
        """Handles git trees (i.e., dirs and subdirs)"""
        tree_entries = []
        tree_entries = self._build_tree_entries(file_hashes)
        tree_content = b"".join(tree_entries)
        return self.store_object("tree", tree_content)

    def create_commit(
        self,
        tree_hash,
        parent_hash=None,
        message="Initial commit",
        author_name="John Doe",
        author_email="john@example.com",
        committer_name="Jane Doe",
        committer_email="jane@example.com",
        timestamp=f"{int(time.mktime(time.gmtime()))} +0000",
    ):
        """Handles a commit object"""
        author_line = f"author {author_name} <{author_email}> {timestamp}"
        committer_line = f"committer {committer_name} <{committer_email}> {timestamp}"

        commit_content = f"tree {tree_hash}\n"
        if parent_hash:
            commit_content += f"parent {parent_hash}\n"
        commit_content += author_line + "\n" + committer_line + "\n\n" + message + "\n"

        commit_hash = self.store_object("commit", commit_content)

        # Update HEAD reference
        HEAD = commit_hash
        with open(f"{self.path}/HEAD", "w+") as head_file:
            head_file.write(HEAD)

        return commit_hash

    def _build_tree_entries(self, files_dict, prefix=""):
        entries = []

        for name, value in files_dict.items():
            entry_path = os.path.join(prefix, name)
            if isinstance(value, dict):  # Subdirectory case
                subtree_entries = self._build_tree_entries(value, entry_path)
                subtree_content = b"".join(subtree_entries)
                subtree_hash = self.store_object("tree", subtree_content)
                print(f"Subtree Hash -> {subtree_hash}")

                mode = b"40000"  # Mode for directory
                entry = (
                    mode
                    + b"\x20"
                    + name.encode()
                    + b"\x00"
                    + binascii.unhexlify(subtree_hash)
                )
                entries.append(entry)
            else:  # File case
                blob_hash = value
                mode = b"100644"  # Mode for regular file
                entry = (
                    mode
                    + b"\x20"
                    + name.encode()
                    + b"\x00"
                    + binascii.unhexlify(blob_hash)
                )
                entries.append(entry)

        return entries


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform actions based on commit type")
    parser.add_argument(
        "--update-file",
        action="store_true",
        help="Update a file from the initial commit to demonstrate parent-commit relationship",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Print git object path and content"
    )
    args = parser.parse_args()
    debug = True if args.debug else False
    is_initial_commit = False if args.update_file else True

    repo = GitRepository(debug=debug)

    if is_initial_commit:
        repo.init()
        print("Initialized empty MyGit repository in .my_git/")

        with open("my_app/file1.txt", "w") as file:
            file.write("")

        with open("my_app/dir1/file2.txt", "w") as file:
            file.write("Hello, world!")

        file1_hash = repo.create_blob("my_app/file1.txt")
        file2_hash = repo.create_blob("my_app/dir1/file2.txt")
        # file3_hash = repo.create_blob("my_app/dir1/dir2/file3.txt")
        print(f"Blob Hash for 'file1.txt' -> {file1_hash}")
        print(f"Blob Hash for 'file2.txt' -> {file2_hash}")
        # print(f"Blob Hash for 'file3.txt' -> {file3_hash}")

        file_hashes = {
            "file1.txt": file1_hash,
            "dir1": {
                "file2.txt": file2_hash,
                # "dir2": {
                #     "file3.txt": file3_hash,
                # }
            },
        }

        tree_hash = repo.create_tree(file_hashes)
        print(f"Tree Hash -> {tree_hash}")

        commit_hash = repo.create_commit(
            tree_hash,
            author_name="Mario Cagalj",
            committer_name="Mario Cagalj",
            committer_email="mcagalj@fesb.hr",
            author_email="mcagalj@fesb.hr",
            message="Initial commit",
            timestamp="1710505992 +0100",  # Hardcoded timestamp for demonstration purposes
        )
        print(f"Commit Hash -> {commit_hash}")
    else:
        # =========================================
        #   Showcase parent-commit relationship
        # =========================================

        # Open and modify file1.txt
        with open("my_app/file1.txt", "a") as file:
            file.write("This is a new line.")

        # Recalculate file and tree hashes
        file1_hash = repo.create_blob("my_app/file1.txt")
        file2_hash = repo.create_blob("my_app/dir1/file2.txt")
        print(f"Blob Hash for 'file1.txt' -> {file1_hash}")
        print(f"Blob Hash for 'file2.txt' -> {file2_hash}")

        file_hashes = {
            "file1.txt": file1_hash,
            "dir1": {
                "file2.txt": file2_hash,
            },
        }

        tree_hash = repo.create_tree(file_hashes)
        print(f"Tree Hash -> {tree_hash}")

        # Get the parent commit from HEAD file
        with open(f"{repo.path}/HEAD", "r") as head_file:
            HEAD = head_file.read().strip()

        # Calculate a new commit
        commit_hash = repo.create_commit(
            parent_hash=HEAD,
            tree_hash=tree_hash,
            message="Update file1",
            timestamp="1710605992 +0100",  # Hardcoded timestamp for demonstration purposes
        )
        print(f"Commit Hash -> {commit_hash}")

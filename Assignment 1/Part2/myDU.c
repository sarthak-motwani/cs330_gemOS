#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

// Function to calculate the space (in bytes) of a directory recursively
long long DirectorySpace(const char *path)
{
	long long size = 0;
	struct stat st;
	if (stat(path, &st) == -1)
	{
		return -1;
	}

	if (S_ISREG(st.st_mode))
	{
		// If it's a file, return its size
		return st.st_size;
	}

	else if (S_ISLNK(st.st_mode))
	{
		// If it's a symbolic link, return the size of the target
		char targetPath[4097];
		ssize_t targetSize = readlink(path, targetPath, sizeof(targetPath));
		targetPath[targetSize] = '\0';
		if (targetSize == -1)
		{
			return -1;
		}
		return DirectorySpace(targetPath);
	}

	else if (S_ISDIR(st.st_mode))
	{
		// if it is a subdirectory
		DIR *dir = opendir(path);
		if (dir == NULL)
		{
			return -1;
		}

		struct dirent *entry;
		while ((entry = readdir(dir)) != NULL)
		{
			if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
			{
				char entryPath[4097];
				strcpy(entryPath, path);
				strcat(entryPath, "/");
				strcat(entryPath, entry->d_name);
				long long subdirectory_ans = DirectorySpace(entryPath);
				if (subdirectory_ans == -1)
				{
					return -1;
				}
				size += subdirectory_ans;
			}
		}

		closedir(dir);
	}
	else
	{
		return -1;
	}
	return size + st.st_size;
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Unable to execute\n");
		exit(EXIT_FAILURE);
	}

	const char *rootDirectory = argv[1];
	unsigned long totalSize = 0;

	DIR *dir = opendir(rootDirectory);
	if (dir == NULL)
	{
		printf("Unable to execute\n");
		exit(EXIT_FAILURE);
	}

	struct stat st_dir;
	if (stat(rootDirectory, &st_dir) == -1)
	{
		printf("Unable to execute\n");
		exit(EXIT_FAILURE);
	}

	totalSize += st_dir.st_size;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
		{
			struct stat st;
			char FullPath[4097];
			strcpy(FullPath, rootDirectory);
			strcat(FullPath, "/");
			strcat(FullPath, entry->d_name);
			if (stat(FullPath, &st) == -1)
			{
				printf("Unable to execute\n");
				exit(EXIT_FAILURE);
			}

			if (S_ISREG(st.st_mode))
			{
				// If it's a file, add its size
				totalSize += st.st_size;
			}
			else if (S_ISLNK(st.st_mode))
			{
				// If it's a symbolic link, add the size of the target
				char targetPath[4097];
				ssize_t targetSize = readlink(FullPath, targetPath, sizeof(targetPath));
				targetPath[targetSize] = '\0';
				if (targetSize == -1)
				{
					printf("Unable to execute\n");
					exit(EXIT_FAILURE);
				}
				long long symlink_ans = DirectorySpace(targetPath);
				if (symlink_ans == -1)
				{
					printf("Unable to execute\n");
					exit(EXIT_FAILURE);
				}
				totalSize += ((unsigned long)symlink_ans);
			}

			else if (S_ISDIR(st.st_mode))
			{
				int fd[2];
				long long buf;
				if (pipe(fd) < 0)
				{
					printf("Unable to execute\n");
					exit(-1);
				}
				int pid = fork();
				if (pid < 0)
				{
					printf("Unable to execute\n");
					exit(-1);
				}
				if (!pid)
				{
					//child writes the size of the subdirectory into the pipe
					close(fd[0]);
					long long sub_dir_sz = DirectorySpace(FullPath);
					ssize_t bytes_written = write(fd[1], &sub_dir_sz, sizeof(long long));
					close(fd[1]);
					exit(0);
				}
				if (pid > 0)
				{
					//parent reads the size of subdirectory from pipe
					close(fd[1]);
					if (read(fd[0], &buf, sizeof(long long)) != sizeof(long long))
					{
						printf("Unable to execute\n");
						exit(-1);
					}
					close(fd[0]);
					if (buf == -1)
					{
						printf("Unable to execute\n");
						exit(-1);
					}
					totalSize += ((unsigned long)buf);
				}
			}
			else
			{
				printf("Unable to execute\n");
				exit(-1);
			}
		}
	}
	printf("%lu\n", totalSize);
	closedir(dir);
	return 0;
}

package org.wildfly.prospero.actions;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.wildfly.prospero.ProsperoLogger;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;

/**
 * A temporary record of all files modified, removed or added during applying a candidate server.
 */
class ApplyStageBackup implements AutoCloseable {

    private final Path backupRoot;
    private final Path serverRoot;

    /**
     * create a record for server at {@code serverRoot}. The recorded files will be stored in {@tempRoot}
     *
     * @param serverRoot - root folder of the server that will be updated
     * @param tempRoot - directory to record changed files in
     */
    public ApplyStageBackup(Path serverRoot, Path tempRoot) {
        if (ProsperoLogger.ROOT_LOGGER.isDebugEnabled()) {
            ProsperoLogger.ROOT_LOGGER.debug("Creating backup record in " + tempRoot);
        }

        this.serverRoot = serverRoot;
        this.backupRoot = tempRoot;

    }

    /**
     * add all the files in the server to cache
     *
     * @throws IOException - if unable to backup the files
     */
    public void recordAll() {
        try {
            Files.walkFileTree(serverRoot, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    if (dir.equals(backupRoot)) {
                        return FileVisitResult.SKIP_SUBTREE;
                    } else {
                        final Path relative = serverRoot.relativize(dir);
                        Files.createDirectories(backupRoot.resolve(relative));
                        return FileVisitResult.CONTINUE;
                    }
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    final Path relative = serverRoot.relativize(file);
                    if (relative.startsWith(Path.of(".installation", ".git"))) {
                        Files.copy(file, backupRoot.resolve(relative));
                    } else {
                        try {
                            Files.createLink(backupRoot.resolve(relative), file);
                        } catch (UnsupportedEncodingException e) {
                            Files.copy(file, backupRoot.resolve(relative));
                        }
                    }
                    return FileVisitResult.CONTINUE;
                };
            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * clean up the cache
     */
    @Override
    public void close() {
        FileUtils.deleteQuietly(backupRoot.toFile());
    }

    /**
     * restore files and directories in {@code targetServer} to the recorded values.
     *
     * @throws IOException - if unable to perform operations of the filesystem
     */
    public void restore() throws IOException {
        if (ProsperoLogger.ROOT_LOGGER.isDebugEnabled()) {
            ProsperoLogger.ROOT_LOGGER.debug("Restoring server from the backup.");
        }

        if (!Files.exists(backupRoot)) {
            throw new RuntimeException("Backup root doesn't exist.");
        }

        // copy backed-up files back into the server
        Files.walkFileTree(backupRoot, restoreModifiedFiles());

        // remove all files added to recorded folders that were not handled by addedFiles
        Files.walkFileTree(serverRoot, deleteNewFiles());
    }

    private SimpleFileVisitor<Path> deleteNewFiles() {
        return new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                final Path relativePath = serverRoot.relativize(file);
                if (!Files.exists(backupRoot.resolve(relativePath))) {
                    if (ProsperoLogger.ROOT_LOGGER.isTraceEnabled()) {
                        ProsperoLogger.ROOT_LOGGER.trace("Removing added file " + relativePath);
                    }

                    Files.delete(file);
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                final Path relativePath = serverRoot.relativize(dir);
                if (!Files.exists(backupRoot.resolve(relativePath))) {
                    if (ProsperoLogger.ROOT_LOGGER.isTraceEnabled()) {
                        ProsperoLogger.ROOT_LOGGER.trace("Removing added directory " + relativePath);
                    }

                    Files.delete(dir);
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                if (dir.equals(backupRoot)) {
                    return FileVisitResult.SKIP_SUBTREE;
                } else {
                    return FileVisitResult.CONTINUE;
                }
            }
        };
    }

    private SimpleFileVisitor<Path> restoreModifiedFiles() {
        return new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                final Path relativePath = backupRoot.relativize(file);

                final Path parentDir = relativePath.getParent();
                if (parentDir != null && !Files.exists(serverRoot.resolve(parentDir))) {
                    if (ProsperoLogger.ROOT_LOGGER.isTraceEnabled()) {
                        ProsperoLogger.ROOT_LOGGER.trace("Recreating removed directory " + parentDir);
                    }

                    Files.createDirectories(serverRoot.resolve(parentDir));
                }

                final Path targetFile = serverRoot.resolve(relativePath);
                if (fileChanged(file, targetFile)) {
                    if (ProsperoLogger.ROOT_LOGGER.isTraceEnabled()) {
                        ProsperoLogger.ROOT_LOGGER.trace("Restoring changed file " + relativePath);
                    }

                    Files.copy(file, targetFile, StandardCopyOption.REPLACE_EXISTING);
                }
                return FileVisitResult.CONTINUE;
            }
        };
    }

    private static boolean fileChanged(Path file, Path targetFile) throws IOException {
        if (!Files.exists(targetFile)) {
            return true;
        }

        try (FileInputStream fis1 = new FileInputStream(targetFile.toFile());
             FileInputStream fis2 = new FileInputStream(file.toFile())){
            return !IOUtils.contentEquals(fis1, fis2);
        }
    }
}

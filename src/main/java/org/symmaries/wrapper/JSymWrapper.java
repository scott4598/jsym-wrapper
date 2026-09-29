package org.symmaries.wrapper;
import org.objectweb.asm.Type;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.LinkOption;
import java.nio.file.StandardCopyOption;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import se.lnu.prosses.api.JSymAnalysisResult;
import se.lnu.prosses.api.JSymAnalyzer;
import se.lnu.prosses.api.JSymAnalyzerBuilder;
import se.lnu.prosses.configs.SymmariesAnalysis;
import se.lnu.prosses.configs.SymmariesHeapDom;

public final class JSymWrapper {

    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper()
                    .enable(
                            SerializationFeature
                                    .INDENT_OUTPUT
                    )
                    .enable(
                            SerializationFeature
                                    .ORDER_MAP_ENTRIES_BY_KEYS
                    );

    private JSymWrapper() {
    }

    public static void main(String[] args) {
        try {
            WrapperArguments arguments = WrapperArguments.parse(args);
            execute(arguments);
        } catch (Exception exception) {
            System.err.println(
                    "Wrapper analysis failed: " + exception.getMessage()
            );
            exception.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void execute(WrapperArguments arguments)
            throws Exception {

        validateReadableFile(
                arguments.inputJar,
                "input JAR"
        );

        validateReadableFile(
                arguments.sourceSinkFile,
                "source/sink file"
        );

        validateExecutable(
                arguments.symmariesExecutable,
                "Symmaries executable"
        );

        for (Path securityStub : arguments.securityStubFiles) {
            validateReadableFile(
                    securityStub,
                    "security-summary stub"
            );
        }
        if (arguments.previousMethodHashes != null) {
            validateReadableFile(
                    arguments.previousMethodHashes,
                    "previous method hash manifest"
            );
        }

        Files.createDirectories(arguments.outputDirectory);

        System.out.println(
                "Starting JSymCompiler frontend analysis"
        );
        System.out.println(
                "Input JAR: " + arguments.inputJar
        );
        System.out.println(
                "Output directory: " + arguments.outputDirectory
        );
        System.out.println(
                "Source/sink file: " + arguments.sourceSinkFile
        );

        JSymAnalyzerBuilder analyzerBuilder =
                new JSymAnalyzerBuilder()
                        .inputJar(arguments.inputJar.toString())
                        .outputDir(arguments.outputDirectory.toString())
                        .sourceSinkFile(arguments.sourceSinkFile.toString())
                        .symmariesPath(
                                arguments.symmariesExecutable.toString()
                        )
                        .analysis(SymmariesAnalysis.IMPLICIT_CONF)
                        .heapDom(SymmariesHeapDom.DUMBALIAS)
                        .exceptionsEnabled(false)
                        .runSyrs(false)
                        .analyzeDependencies(false)
                        .buildMavenProject(false);

        if (arguments.extraClasspath != null) {
            analyzerBuilder.extraClasspath(
                    arguments.extraClasspath
            );
        }

        for (Path securityStub : arguments.securityStubFiles) {
            analyzerBuilder.securitySummaryFile(
                    securityStub.toString()
            );
        }

        JSymAnalyzer analyzer = analyzerBuilder.build();

        JSymAnalysisResult result = analyzer.analyze();

        Path actualOutputDirectory = Paths.get(
                result.getOutputDirectory()
        ).toAbsolutePath().normalize();

        System.out.println(
                "JSymCompiler completed in "
                        + result.getExecutionTimeMillis()
                        + " ms"
        );

        System.out.println(
                "Analysed classes: "
                        + result.getAnalyzedClasses().size()
        );

        validateFrontendOutputs(actualOutputDirectory);

        classifyDirectChanges(
                arguments,
                actualOutputDirectory
        );
        
        prepareLegacySyrsCompatibilityLink(
                actualOutputDirectory
        );

        Path generatedCommand = actualOutputDirectory.resolve(
                "syrsCommand.command"
        );

        Path wrapperCommand = actualOutputDirectory.resolve(
                "wrapper-syrs-command.sh"
        );

        Files.copy(
                generatedCommand,
                wrapperCommand,
                StandardCopyOption.REPLACE_EXISTING
        );

        wrapperCommand.toFile().setExecutable(true);

        System.out.println(
                "Executing generated Symmaries command: "
                        + wrapperCommand
        );

        int symmariesExitCode = runSymmaries(
                wrapperCommand,
                actualOutputDirectory
        );

        if (symmariesExitCode != 0) {
            throw new IOException(
                    "Symmaries exited with code "
                            + symmariesExitCode
                            + ". See "
                            + actualOutputDirectory.resolve(
                            "wrapper-syrs-stdout.log"
                    )
                            + " and "
                            + actualOutputDirectory.resolve(
                            "wrapper-syrs-stderr.log"
                    )
            );
        }
        removeLegacySyrsCompatibilityLink(
                actualOutputDirectory
        );

        validateSymmariesOutputs(actualOutputDirectory);

        System.out.println(
                "Wrapper analysis completed successfully"
        );
        System.out.println(
                "Results directory: " + actualOutputDirectory
        );
    }

    private static void classifyDirectChanges(
            WrapperArguments arguments,
            Path outputDirectory)
            throws IOException {

        Map<String, String> currentHashes =
                BytecodeMethodHasher.computeHashes(
                        arguments.inputJar
                );

        Path currentHashFile =
                outputDirectory.resolve(
                        "methodHashmap.json"
                );

        writeMethodHashes(
                currentHashFile,
                currentHashes
        );

        System.out.println(
                "Current bytecode method hashes: "
                        + currentHashes.size()
        );

        Path incrementalDirectory =
                outputDirectory.resolve(
                        "incremental"
                );

        Files.createDirectories(
                incrementalDirectory
        );

        Path affectedMethodsFile =
                incrementalDirectory.resolve(
                        "affected.meth_files"
                );

        /*
         * Full analysis has no previous version to compare.
         * Symmaries still expects the file to exist, but the normal
         * all.meth_files input already supplies every current method.
         */
        if (arguments.previousMethodHashes == null) {
            Files.write(
                    affectedMethodsFile,
                    Collections.<String>emptyList(),
                    StandardCharsets.UTF_8
            );

            return;
        }

        Map<String, String> previousHashes =
                readMethodHashes(
                        arguments.previousMethodHashes
                );

        List<String> changedMethods =
                new ArrayList<String>();

        List<String> unchangedMethods =
                new ArrayList<String>();

        for (Map.Entry<String, String> entry :
                new TreeMap<String, String>(
                        currentHashes
                ).entrySet()) {

            String methodIdentifier =
                    entry.getKey();

            String currentHash =
                    entry.getValue();

            String previousHash =
                    previousHashes.get(
                            methodIdentifier
                    );

            if (previousHash == null
                    || !previousHash.equals(
                    currentHash
            )) {

                changedMethods.add(
                        methodIdentifier
                );
            } else {
                unchangedMethods.add(
                        methodIdentifier
                );
            }
        }

        /*
         * Only current methods with a generated .meth file can be passed
         * to Symmaries. Abstract, native, skipped, or failed methods are
         * therefore omitted from affected.meth_files.
         */
        List<String> affectedMethodPaths =
                new ArrayList<String>();

        List<String> changedWithoutMeth =
                new ArrayList<String>();

        for (String methodIdentifier :
                changedMethods) {

            Path methodFile =
                    methodFileForIdentifier(
                            outputDirectory,
                            methodIdentifier
                    );

            if (Files.isRegularFile(methodFile)) {
                affectedMethodPaths.add(
                        methodFile.toAbsolutePath()
                                .normalize()
                                .toString()
                );
            } else {
                changedWithoutMeth.add(
                        methodIdentifier
                );
            }
        }

        Collections.sort(
                affectedMethodPaths
        );

        Files.write(
                affectedMethodsFile,
                affectedMethodPaths,
                StandardCharsets.UTF_8
        );

        Files.write(
                incrementalDirectory.resolve(
                        "directly-changed-methods.txt"
                ),
                changedMethods,
                StandardCharsets.UTF_8
        );

        Files.write(
                incrementalDirectory.resolve(
                        "unchanged-methods.txt"
                ),
                unchangedMethods,
                StandardCharsets.UTF_8
        );

        Files.write(
                incrementalDirectory.resolve(
                        "changed-without-meth.txt"
                ),
                changedWithoutMeth,
                StandardCharsets.UTF_8
        );

        Map<String, Object> classification =
                new LinkedHashMap<String, Object>();

        classification.put(
                "formatVersion",
                1
        );

        classification.put(
                "hashSchema",
                BytecodeMethodHasher.HASH_SCHEMA
        );

        classification.put(
                "implicitChangePropagation",
                false
        );

        classification.put(
                "changed",
                changedMethods
        );

        classification.put(
                "unchanged",
                unchangedMethods
        );

        classification.put(
                "affectedMethFiles",
                affectedMethodPaths
        );

        classification.put(
                "changedWithoutMeth",
                changedWithoutMeth
        );

        OBJECT_MAPPER.writeValue(
                incrementalDirectory.resolve(
                        "method-classification.json"
                ).toFile(),
                classification
        );

        System.out.println(
                "Previous bytecode method hashes: "
                        + previousHashes.size()
        );

        System.out.println(
                "Directly changed methods: "
                        + changedMethods.size()
        );

        System.out.println(
                "Affected .meth files: "
                        + affectedMethodPaths.size()
        );

        System.out.println(
                "Unchanged methods: "
                        + unchangedMethods.size()
        );

        if (!changedWithoutMeth.isEmpty()) {
            System.out.println(
                    "Changed methods without generated .meth: "
                            + changedWithoutMeth.size()
            );
        }
    }

    private static void prepareLegacySyrsCompatibilityLink(
        Path outputDirectory)
        throws IOException {

    Path incrementalDirectory =
            outputDirectory.resolve("incremental");

    Files.createDirectories(
            incrementalDirectory
    );

    Path affectedMethods =
            incrementalDirectory.resolve(
                    "affected.meth_files"
            );

    if (!Files.isRegularFile(affectedMethods)) {
        throw new IOException(
                "Affected-method file is missing: "
                        + affectedMethods
        );
    }

    Path compatibilityPath =
            outputDirectory.resolve("Syrs");

    if (Files.exists(
            compatibilityPath,
            LinkOption.NOFOLLOW_LINKS
    )) {
        if (Files.isSymbolicLink(
                compatibilityPath
        )) {
            Files.delete(
                    compatibilityPath
            );
        } else {
            throw new IOException(
                    "Cannot create Symmaries compatibility "
                            + "link because the path already "
                            + "exists and is not a symbolic link: "
                            + compatibilityPath
            );
        }
    }

    /*
     * <output>/Syrs -> .
     *
     * This allows the current Symmaries build to resolve
     * Syrs/Meth and Syrs/incremental while preserving the
     * root-level output layout.
     */
    Files.createSymbolicLink(
            compatibilityPath,
            Paths.get(".")
    );
}       

private static void removeLegacySyrsCompatibilityLink(
        Path outputDirectory)
        throws IOException {

    Path compatibilityPath =
            outputDirectory.resolve("Syrs");

    if (!Files.exists(
            compatibilityPath,
            LinkOption.NOFOLLOW_LINKS
    )) {
        return;
    }

    if (!Files.isSymbolicLink(
            compatibilityPath
    )) {
        throw new IOException(
                "Expected the Symmaries compatibility path "
                        + "to be a symbolic link: "
                        + compatibilityPath
        );
    }

    Files.delete(
            compatibilityPath
    );
}

    private static Path methodFileForIdentifier(
            Path outputDirectory,
            String methodIdentifier)
            throws IOException {

        int separator =
                methodIdentifier.indexOf('#');

        if (separator <= 0
                || separator
                == methodIdentifier.length() - 1) {

            throw new IOException(
                    "Invalid JVM method identifier: "
                            + methodIdentifier
            );
        }

        String className =
                methodIdentifier.substring(
                        0,
                        separator
                );

        String methodAndDescriptor =
                methodIdentifier.substring(
                        separator + 1
                );

        int descriptorStart =
                methodAndDescriptor.indexOf('(');

        if (descriptorStart <= 0) {
            throw new IOException(
                    "Invalid JVM method descriptor: "
                            + methodIdentifier
            );
        }

        String methodName =
                methodAndDescriptor.substring(
                        0,
                        descriptorStart
                );

        String descriptor =
                methodAndDescriptor.substring(
                        descriptorStart
                );

        int packageSeparator =
                className.lastIndexOf('.');

        String simpleClassName =
                packageSeparator < 0
                        ? className
                        : className.substring(
                        packageSeparator + 1
                );

        if ("<init>".equals(methodName)) {
            methodName = "init";
        } else if ("<clinit>".equals(methodName)) {
            methodName = "clinit";
        }

        StringBuilder methodKey =
                new StringBuilder();

        methodKey
                .append(simpleClassName)
                .append('_')
                .append(methodName);

        for (Type argumentType :
                Type.getArgumentTypes(
                        descriptor
                )) {

            methodKey
                    .append('_')
                    .append(
                            methodParameterKey(
                                    argumentType
                            )
                    );
        }

        return outputDirectory
                .resolve("Meth")
                .resolve(
                        methodKey.toString()
                                + ".meth"
                );
    }

    private static String methodParameterKey(
            Type argumentType) {

        if (argumentType.getSort()
                == Type.ARRAY) {

            StringBuilder key =
                    new StringBuilder();

            Type elementType =
                    argumentType.getElementType();

            if (elementType.getSort()
                    == Type.OBJECT) {

                key.append(
                        elementType.getClassName()
                );
            } else {
                key.append(
                        elementType.getClassName()
                );
            }

            for (int dimension = 0;
                 dimension
                         < argumentType.getDimensions();
                 dimension++) {

                key.append("_arr");
            }

            return key.toString();
        }

        return argumentType.getClassName();
    }

    private static Map<String, String> readMethodHashes(
            Path hashFile)
            throws IOException {

        Map<String, String> hashes =
                OBJECT_MAPPER.readValue(
                        hashFile.toFile(),
                        new TypeReference<
                                Map<String, String>
                                >() {
                        }
                );

        if (hashes == null) {
            throw new IOException(
                    "Previous method hash manifest "
                            + "contains no JSON object: "
                            + hashFile
            );
        }

        Map<String, String> validated =
                new TreeMap<String, String>();

        for (Map.Entry<String, String> entry :
                hashes.entrySet()) {

            String method = entry.getKey();
            String hash = entry.getValue();

            if (method == null
                    || method.trim().isEmpty()) {

                throw new IOException(
                        "Previous method hash manifest "
                                + "contains an empty "
                                + "method identifier"
                );
            }

            if (hash == null
                    || hash.trim().isEmpty()) {

                throw new IOException(
                        "Previous method hash manifest "
                                + "contains an empty hash "
                                + "for "
                                + method
                );
            }

            validated.put(method, hash);
        }

        return validated;
    }

    private static void writeMethodHashes(
            Path outputFile,
            Map<String, String> hashes)
            throws IOException {

        OBJECT_MAPPER.writeValue(
                outputFile.toFile(),
                new TreeMap<String, String>(
                        hashes
                )
        );

        validateReadableFile(
                outputFile,
                "current method hash manifest"
        );
    }

    private static int runSymmaries(
            Path commandFile,
            Path outputDirectory)
            throws IOException, InterruptedException {

        Path stdout = outputDirectory.resolve(
                "wrapper-syrs-stdout.log"
        );

        Path stderr = outputDirectory.resolve(
                "wrapper-syrs-stderr.log"
        );


        ProcessBuilder processBuilder = new ProcessBuilder(
                "/bin/bash",
                commandFile.toString()
        );

        processBuilder.environment().put(
                "heapDomain",
                "dumbalias"
        );

        processBuilder.environment().put(
                "variant",
                ""
        );

        processBuilder.directory(
                outputDirectory.toFile()
        );

        processBuilder.redirectOutput(
                stdout.toFile()
        );

        processBuilder.redirectError(
                stderr.toFile()
        );

        Process process = processBuilder.start();
        return process.waitFor();
    }

    private static void validateExistingFile(
            Path path,
            String description)
            throws IOException {

        if (!Files.isRegularFile(path)) {
            throw new IOException(
                    description + " is missing: " + path
            );
        }

        if (!Files.isReadable(path)) {
            throw new IOException(
                    description + " is not readable: " + path
            );
        }
    }

    private static void validateFrontendOutputs(
            Path outputDirectory)
            throws IOException {

        validateReadableFile(
                outputDirectory.resolve("types.classes"),
                "JSymCompiler types.classes"
        );

        validateReadableFile(
                outputDirectory.resolve(
                        "Meth/all.meth_files"
                ),
                "JSymCompiler all.meth_files"
        );

        validateExistingFile(
                outputDirectory.resolve(
                        "Meth/all.secstubs"
                ),
                "JSymCompiler all.secstubs"
        );

        validateReadableFile(
                outputDirectory.resolve(
                        "syrsCommand.command"
                ),
                "generated Symmaries command"
        );
    }

    private static void validateSymmariesOutputs(
            Path outputDirectory)
            throws IOException {

        Path results = outputDirectory.resolve(
                "results.secsums"
        );

        validateReadableFile(
                results,
                "Symmaries results.secsums"
        );

        Path statistics = outputDirectory.resolve(
                "results.meth_stats"
        );

        if (!Files.isRegularFile(statistics)) {
            System.out.println(
                    "Warning: Symmaries did not produce "
                            + statistics
            );
        }
    }

    private static void validateExecutable(
            Path path,
            String description)
            throws IOException {

        if (!Files.isRegularFile(path)) {
            throw new IOException(
                    description + " is missing: " + path
            );
        }

        if (!Files.isExecutable(path)) {
            throw new IOException(
                    description + " is not executable: " + path
            );
        }
    }

    private static void validateReadableFile(
            Path path,
            String description)
            throws IOException {

        if (!Files.isRegularFile(path)) {
            throw new IOException(
                    description + " is missing: " + path
            );
        }

        if (!Files.isReadable(path)) {
            throw new IOException(
                    description + " is not readable: " + path
            );
        }

        if (Files.size(path) == 0) {
            throw new IOException(
                    description + " is empty: " + path
            );
        }
    }

    private static final class WrapperArguments {

        private final Path inputJar;
        private final Path outputDirectory;
        private final Path sourceSinkFile;
        private final Path symmariesExecutable;
        private final String extraClasspath;
        private final java.util.List<Path> securityStubFiles;
        private final Path previousMethodHashes;

        private WrapperArguments(
                Path inputJar,
                Path outputDirectory,
                Path sourceSinkFile,
                Path symmariesExecutable,
                String extraClasspath,
                java.util.List<Path> securityStubFiles,
                Path previousMethodHashes) {

            this.inputJar = inputJar;
            this.outputDirectory = outputDirectory;
            this.sourceSinkFile = sourceSinkFile;
            this.symmariesExecutable = symmariesExecutable;
            this.extraClasspath = extraClasspath;
            this.securityStubFiles = securityStubFiles;
            this.previousMethodHashes = previousMethodHashes;
        }

        private static WrapperArguments parse(String[] args) {

            Path inputJar = null;
            Path outputDirectory = null;
            Path sourceSinkFile = null;
            Path symmariesExecutable = null;
            String extraClasspath = null;
            Path previousMethodHashes = null;

            java.util.List<Path> securityStubFiles =
                    new java.util.ArrayList<Path>();

            for (int index = 0;
                 index < args.length;
                 index++) {

                String argument = args[index];

                if ("--input".equals(argument)) {
                    inputJar = requiredPath(
                            args,
                            ++index,
                            argument
                    );
                } else if ("--output".equals(argument)) {
                    outputDirectory = requiredPath(
                            args,
                            ++index,
                            argument
                    );
                } else if ("--sources-sinks".equals(argument)) {
                    sourceSinkFile = requiredPath(
                            args,
                            ++index,
                            argument
                    );
                } else if ("--symmaries".equals(argument)) {
                    symmariesExecutable = requiredPath(
                            args,
                            ++index,
                            argument
                    );
                } else if ("--classpath".equals(argument)) {
                    extraClasspath = requiredValue(
                            args,
                            ++index,
                            argument
                    );
                } else if ("--security-stub".equals(argument)) {
                    securityStubFiles.add(
                            requiredPath(
                                    args,
                                    ++index,
                                    argument
                            )
                    );
                } else if ("--previous-hashes".equals(argument)) {
                    previousMethodHashes = requiredPath(
                            args,
                            ++index,
                            argument
                    );
                } else {
                    throw new IllegalArgumentException(
                            "Unknown wrapper argument: "
                                    + argument
                    );
                }
            }

            if (inputJar == null) {
                throw new IllegalArgumentException(
                        "--input is required"
                );
            }

            if (outputDirectory == null) {
                throw new IllegalArgumentException(
                        "--output is required"
                );
            }

            if (sourceSinkFile == null) {
                throw new IllegalArgumentException(
                        "--sources-sinks is required"
                );
            }

            if (symmariesExecutable == null) {
                throw new IllegalArgumentException(
                        "--symmaries is required"
                );
            }

            return new WrapperArguments(
                    inputJar,
                    outputDirectory,
                    sourceSinkFile,
                    symmariesExecutable,
                    extraClasspath,
                    securityStubFiles,
                    previousMethodHashes
            );
        }

        private static Path requiredPath(
                String[] args,
                int index,
                String option) {

            return java.nio.file.Paths.get(
                    requiredValue(args, index, option)
            ).toAbsolutePath().normalize();
        }

        private static String requiredValue(
                String[] args,
                int index,
                String option) {

            if (index >= args.length) {
                throw new IllegalArgumentException(
                        option + " requires a value"
                );
            }

            String value = args[index];

            if (value == null || value.trim().isEmpty()) {
                throw new IllegalArgumentException(
                        option + " requires a non-empty value"
                );
            }

            return value;
        }
    }
}
package org.symmaries.wrapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class BytecodeMethodHasher {

    static final String HASH_SCHEMA = "bc-v2";

    private BytecodeMethodHasher() {
    }

    static Map<String, String> computeHashes(
            Path jarPath)
            throws IOException {

        Map<String, String> hashes =
                new LinkedHashMap<String, String>();

        try (JarFile jarFile =
                     new JarFile(jarPath.toFile())) {

            Enumeration<JarEntry> entries =
                    jarFile.entries();

            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String entryName = entry.getName();

                if (!entryName.endsWith(".class")) {
                    continue;
                }

                if ("module-info.class".equals(entryName)
                        || entryName.endsWith(
                        "/module-info.class"
                )) {
                    continue;
                }

                if (entryName.startsWith(
                        "META-INF/versions/"
                )) {
                    continue;
                }

                try (InputStream inputStream =
                             jarFile.getInputStream(entry)) {

                    ClassReader classReader =
                            new ClassReader(inputStream);

                    classReader.accept(
                            new ClassVisitor(Opcodes.ASM9) {

                                private String className;

                                @Override
                                public void visit(
                                        int version,
                                        int access,
                                        String name,
                                        String signature,
                                        String superName,
                                        String[] interfaces) {

                                    className =
                                            name.replace(
                                                    '/',
                                                    '.'
                                            );
                                }

                                @Override
                                public MethodVisitor visitMethod(
                                        int access,
                                        String name,
                                        String descriptor,
                                        String signature,
                                        String[] exceptions) {

                                    if ((access
                                            & Opcodes.ACC_SYNTHETIC)
                                            != 0) {
                                        return null;
                                    }

                                    if ((access
                                            & Opcodes.ACC_BRIDGE)
                                            != 0) {
                                        return null;
                                    }

                                    IdentityHashMap<
                                            Label,
                                            Integer
                                            > labelIdentifiers =
                                            new IdentityHashMap<
                                                    Label,
                                                    Integer
                                                    >();

                                    int[] nextLabelIdentifier =
                                            new int[] {0};

                                    java.util.function.Function<
                                            Label,
                                            Integer
                                            > labelIdentifier =
                                            label -> {

                                                Integer existing =
                                                        labelIdentifiers
                                                                .get(
                                                                        label
                                                                );

                                                if (existing
                                                        != null) {
                                                    return existing;
                                                }

                                                int identifier =
                                                        nextLabelIdentifier[
                                                                0
                                                                ]++;

                                                labelIdentifiers.put(
                                                        label,
                                                        identifier
                                                );

                                                return identifier;
                                            };

                                    StringBuilder fingerprint =
                                            new StringBuilder();

                                    fingerprint
                                            .append("M:")
                                            .append(name)
                                            .append(descriptor)
                                            .append('\n');

                                    fingerprint
                                            .append("A:")
                                            .append(access)
                                            .append('\n');

                                    if (exceptions != null) {
                                        String[] sortedExceptions =
                                                exceptions.clone();

                                        Arrays.sort(
                                                sortedExceptions
                                        );

                                        for (String exception :
                                                sortedExceptions) {

                                            fingerprint
                                                    .append("E:")
                                                    .append(exception)
                                                    .append('\n');
                                        }
                                    }

                                    return new MethodVisitor(
                                            Opcodes.ASM9
                                    ) {

                                        @Override
                                        public void visitInsn(
                                                int opcode) {

                                            fingerprint
                                                    .append("I:")
                                                    .append(opcode)
                                                    .append('\n');
                                        }

                                        @Override
                                        public void visitIntInsn(
                                                int opcode,
                                                int operand) {

                                            fingerprint
                                                    .append("II:")
                                                    .append(opcode)
                                                    .append(':')
                                                    .append(operand)
                                                    .append('\n');
                                        }

                                        @Override
                                        public void visitVarInsn(
                                                int opcode,
                                                int variable) {

                                            fingerprint
                                                    .append("VI:")
                                                    .append(opcode)
                                                    .append(':')
                                                    .append(variable)
                                                    .append('\n');
                                        }

                                        @Override
                                        public void visitTypeInsn(
                                                int opcode,
                                                String type) {

                                            fingerprint
                                                    .append("TI:")
                                                    .append(opcode)
                                                    .append(':')
                                                    .append(type)
                                                    .append('\n');
                                        }

                                        @Override
                                        public void visitFieldInsn(
                                                int opcode,
                                                String owner,
                                                String fieldName,
                                                String fieldDescriptor) {

                                            fingerprint
                                                    .append("FI:")
                                                    .append(opcode)
                                                    .append(':')
                                                    .append(owner)
                                                    .append(':')
                                                    .append(fieldName)
                                                    .append(':')
                                                    .append(
                                                            fieldDescriptor
                                                    )
                                                    .append('\n');
                                        }

                                        @Override
                                        public void visitMethodInsn(
                                                int opcode,
                                                String owner,
                                                String methodName,
                                                String methodDescriptor,
                                                boolean isInterface) {

                                            fingerprint
                                                    .append("MI:")
                                                    .append(opcode)
                                                    .append(':')
                                                    .append(owner)
                                                    .append(':')
                                                    .append(methodName)
                                                    .append(':')
                                                    .append(
                                                            methodDescriptor
                                                    )
                                                    .append(':')
                                                    .append(isInterface)
                                                    .append('\n');
                                        }

                                        @Override
                                        public void visitLabel(
                                                Label label) {

                                            fingerprint
                                                    .append("LABEL:")
                                                    .append(
                                                            labelIdentifier
                                                                    .apply(
                                                                            label
                                                                    )
                                                    )
                                                    .append('\n');
                                        }

                                        @Override
                                        public void visitJumpInsn(
                                                int opcode,
                                                Label label) {

                                            fingerprint
                                                    .append("JI:")
                                                    .append(opcode)
                                                    .append(':')
                                                    .append(
                                                            labelIdentifier
                                                                    .apply(
                                                                            label
                                                                    )
                                                    )
                                                    .append('\n');
                                        }

                                        @Override
                                        public void visitLdcInsn(
                                                Object value) {

                                            fingerprint
                                                    .append("LDC:")
                                                    .append(
                                                            value == null
                                                                    ? "null"
                                                                    : value
                                                                    .getClass()
                                                                    .getName()
                                                    )
                                                    .append(':')
                                                    .append(
                                                            String.valueOf(
                                                                    value
                                                            )
                                                    )
                                                    .append('\n');
                                        }

                                        @Override
                                        public void
                                        visitTableSwitchInsn(
                                                int minimum,
                                                int maximum,
                                                Label defaultLabel,
                                                Label... labels) {

                                            fingerprint
                                                    .append("TS:")
                                                    .append(minimum)
                                                    .append(':')
                                                    .append(maximum)
                                                    .append(
                                                            ":default="
                                                    )
                                                    .append(
                                                            labelIdentifier
                                                                    .apply(
                                                                            defaultLabel
                                                                    )
                                                    );

                                            if (labels != null) {
                                                for (Label label :
                                                        labels) {

                                                    fingerprint
                                                            .append(':')
                                                            .append(
                                                                    labelIdentifier
                                                                            .apply(
                                                                                    label
                                                                            )
                                                            );
                                                }
                                            }

                                            fingerprint.append('\n');
                                        }

                                        @Override
                                        public void
                                        visitLookupSwitchInsn(
                                                Label defaultLabel,
                                                int[] keys,
                                                Label[] labels) {

                                            fingerprint
                                                    .append(
                                                            "LS:default="
                                                    )
                                                    .append(
                                                            labelIdentifier
                                                                    .apply(
                                                                            defaultLabel
                                                                    )
                                                    );

                                            if (keys != null
                                                    && labels != null) {

                                                for (int index = 0;
                                                     index < keys.length;
                                                     index++) {

                                                    fingerprint
                                                            .append(':')
                                                            .append(
                                                                    keys[index]
                                                            )
                                                            .append("->")
                                                            .append(
                                                                    labelIdentifier
                                                                            .apply(
                                                                                    labels[
                                                                                            index
                                                                                            ]
                                                                            )
                                                            );
                                                }
                                            }

                                            fingerprint.append('\n');
                                        }

                                        @Override
                                        public void visitIincInsn(
                                                int variable,
                                                int increment) {

                                            fingerprint
                                                    .append("IINC:")
                                                    .append(variable)
                                                    .append(':')
                                                    .append(increment)
                                                    .append('\n');
                                        }

                                        @Override
                                        public void
                                        visitMultiANewArrayInsn(
                                                String
                                                        arrayDescriptor,
                                                int dimensions) {

                                            fingerprint
                                                    .append("MARRAY:")
                                                    .append(
                                                            arrayDescriptor
                                                    )
                                                    .append(':')
                                                    .append(dimensions)
                                                    .append('\n');
                                        }

                                        @Override
                                        public void visitTryCatchBlock(
                                                Label start,
                                                Label end,
                                                Label handler,
                                                String type) {

                                            fingerprint
                                                    .append("TC:")
                                                    .append(
                                                            type == null
                                                                    ? "<finally>"
                                                                    : type
                                                    )
                                                    .append(':')
                                                    .append(
                                                            labelIdentifier
                                                                    .apply(
                                                                            start
                                                                    )
                                                    )
                                                    .append(':')
                                                    .append(
                                                            labelIdentifier
                                                                    .apply(
                                                                            end
                                                                    )
                                                    )
                                                    .append(':')
                                                    .append(
                                                            labelIdentifier
                                                                    .apply(
                                                                            handler
                                                                    )
                                                    )
                                                    .append('\n');
                                        }

                                        @Override
                                        public void visitEnd() {
                                            String methodIdentifier =
                                                    className
                                                            + "#"
                                                            + name
                                                            + descriptor;

                                            hashes.put(
                                                    methodIdentifier,
                                                    HASH_SCHEMA
                                                            + ":"
                                                            + sha256(
                                                            fingerprint
                                                                    .toString()
                                                    )
                                            );
                                        }
                                    };
                                }
                            },
                            ClassReader.SKIP_DEBUG
                                    | ClassReader.SKIP_FRAMES
                    );
                } catch (RuntimeException exception) {
                    throw new IOException(
                            "Failed to hash class "
                                    + entryName,
                            exception
                    );
                }
            }
        }

        return hashes;
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest =
                    MessageDigest.getInstance(
                            "SHA-256"
                    );

            byte[] bytes = digest.digest(
                    value.getBytes(
                            StandardCharsets.UTF_8
                    )
            );

            StringBuilder output =
                    new StringBuilder(
                            bytes.length * 2
                    );

            for (byte current : bytes) {
                output.append(
                        String.format(
                                "%02x",
                                current & 0xff
                        )
                );
            }

            return output.toString();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "SHA-256 is unavailable",
                    exception
            );
        }
    }
}
# Third-party notices

The author-provided project has no author-selected license in the supplied snapshot. No third-party license below grants rights to the original project code or data.

The prebuilt `dist/phap-tools.jar` incorporates the Maven runtime dependencies pinned by `tools/pom.xml`:

| Component | Version | License / upstream |
|---|---|---|
| Bouncy Castle Java provider | 1.86 | MIT; see `dist/licenses/bcprov-jdk18on-1.86-META-INF_LICENSE.md` and https://www.bouncycastle.org/licence.html |
| Kotlin standard library | 1.9.22 | Apache License 2.0; https://github.com/JetBrains/kotlin |
| JetBrains annotations | 13.0 | Apache License 2.0; https://github.com/JetBrains/java-annotations |
| Gson | 2.13.2 | Apache License 2.0; https://github.com/google/gson |
| Error Prone annotations | 2.41.0 | Apache License 2.0; https://github.com/google/error-prone |

A copy of the Apache License 2.0 text is supplied at `dist/licenses/APACHE-2.0.txt`. Bouncy Castle's bundled license also remains within the execution JAR. Maven resolves the components and their POM metadata when rebuilding. Test-only JUnit and Hamcrest and Android/Gradle dependencies retain their upstream licenses and are not bundled by this repository's Maven execution artifact.

The Gradle wrapper JAR is retained as supplied; Gradle is distributed under Apache License 2.0 (https://github.com/gradle/gradle). Android build and downloaded dependencies have their own upstream notices. The optional Matplotlib plotting environment is not redistributed here; it is listed in `experiments/plot-requirements.txt`.

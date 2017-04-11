mvn test-compile exec:exec -Dexec.executable="java" -Dexec.args="-classpath %classpath io.nitor.vertx.acme4j.TestApp" -Dexec.classpathScope=test

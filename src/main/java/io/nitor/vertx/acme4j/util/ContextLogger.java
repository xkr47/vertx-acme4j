/*
 * Copyright 2017 Jonas Berlin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.nitor.vertx.acme4j.util;

import io.vertx.core.logging.Logger;

import static io.vertx.core.logging.LoggerFactory.getLogger;

public class ContextLogger extends Logger {
    private final String prefix;

    public ContextLogger(Class<?> clazz, String... context) {
        super(getLogger(clazz).getDelegate());
        this.prefix = '<' + String.join(" ", context) + "> ";
    }

    @Override
    public void fatal(Object message) {
        super.fatal(prefix + message);
    }

    @Override
    public void fatal(Object message, Throwable t) {
        super.fatal(prefix + message, t);
    }

    @Override
    public void error(Object message) {
        super.error(prefix + message);
    }

    @Override
    public void error(Object message, Throwable t) {
        super.error(prefix + message, t);
    }

    @Override
    public void error(Object message, Object... objects) {
        super.error(prefix + message, objects);
    }

    @Override
    public void error(Object message, Throwable t, Object... objects) {
        super.error(prefix + message, t, objects);
    }

    @Override
    public void warn(Object message) {
        super.warn(prefix + message);
    }

    @Override
    public void warn(Object message, Throwable t) {
        super.warn(prefix + message, t);
    }

    @Override
    public void warn(Object message, Object... objects) {
        super.warn(prefix + message, objects);
    }

    @Override
    public void warn(Object message, Throwable t, Object... objects) {
        super.warn(prefix + message, t, objects);
    }

    @Override
    public void info(Object message) {
        super.info(prefix + message);
    }

    @Override
    public void info(Object message, Throwable t) {
        super.info(prefix + message, t);
    }

    @Override
    public void info(Object message, Object... objects) {
        super.info(prefix + message, objects);
    }

    @Override
    public void info(Object message, Throwable t, Object... objects) {
        super.info(prefix + message, t, objects);
    }

    @Override
    public void debug(Object message) {
        super.debug(prefix + message);
    }

    @Override
    public void debug(Object message, Throwable t) {
        super.debug(prefix + message, t);
    }

    @Override
    public void debug(Object message, Object... objects) {
        super.debug(prefix + message, objects);
    }

    @Override
    public void debug(Object message, Throwable t, Object... objects) {
        super.debug(prefix + message, t, objects);
    }

    @Override
    public void trace(Object message) {
        super.trace(prefix + message);
    }

    @Override
    public void trace(Object message, Throwable t) {
        super.trace(prefix + message, t);
    }

    @Override
    public void trace(Object message, Object... objects) {
        super.trace(prefix + message, objects);
    }

    @Override
    public void trace(Object message, Throwable t, Object... objects) {
        super.trace(prefix + message, t, objects);
    }
}

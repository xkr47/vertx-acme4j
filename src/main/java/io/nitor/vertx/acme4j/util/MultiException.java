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

import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.List;
import java.util.function.Consumer;

public class MultiException extends RuntimeException {
    public final List<Throwable> exceptions;

    public static Throwable wrapIfNeeded(List<Throwable> exceptions) {
        if (exceptions == null || exceptions.isEmpty()) {
            throw new IllegalArgumentException("No exceptions! Can't take this!");
        }
        if (exceptions.size() == 1) {
            return exceptions.get(0);
        }
        return new MultiException(exceptions);
    }

    private MultiException(List<Throwable> exceptions) {
        this.exceptions = exceptions;
    }

    @Override
    public void printStackTrace(PrintStream s) {
        super.printStackTrace(s);
        exceptions.forEach(new Consumer<Throwable>() {
            int id = 1;
            @Override
            public void accept(Throwable t) {
                s.println("--- MultiException " + id+++ "/" + exceptions.size());
                t.printStackTrace(s);
            }
        });
    }

    @Override
    public void printStackTrace(PrintWriter s) {
        super.printStackTrace(s);
        exceptions.forEach(new Consumer<Throwable>() {
            int id = 1;
            @Override
            public void accept(Throwable t) {
                s.println("--- MultiException " + id+++ "/" + exceptions.size());
                t.printStackTrace(s);
            }
        });
    }
}

package com.github.thomasdarimont.keycloak.mcp.backend.prompts;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The text of a prompt file with its placeholders: {@code {{name}}} is the argument's
 * value, {@code {{#name}}...{{/name}}} a part that stays when the argument was given,
 * {@code {{^name}}...{{/name}}} one that stays when it was not. Parts nest. A part's tag
 * alone on a line takes the line with it, so a step that depends on an argument leaves no
 * gap. Nothing else: no expressions, no loops, no includes.
 */
final class PromptTemplate {

    private static final Pattern TAG = Pattern.compile("\\{\\{([#^/]?)\\s*([^{}\\s]*)\\s*}}");

    /** A part's tag that is all its line holds: the line goes, the tag stays. */
    private static final Pattern STANDALONE = Pattern.compile("(?m)^[ \\t]*(\\{\\{[#^/][^{}]*}})[ \\t]*\\r?\\n");

    private sealed interface Node permits Text, Value, Part {
    }

    private record Text(String text) implements Node {
    }

    private record Value(String name) implements Node {
    }

    private record Part(String name, boolean whenGiven, List<Node> nodes) implements Node {
    }

    private final List<Node> nodes;

    private PromptTemplate(List<Node> nodes) {
        this.nodes = nodes;
    }

    /**
     * @param arguments the names a placeholder may use
     * @throws IllegalArgumentException a placeholder of an undeclared argument, a part
     * that is not closed or closed out of turn
     */
    static PromptTemplate parse(String text, Set<String> arguments) {
        String source = STANDALONE.matcher(text).replaceAll("$1");
        Deque<Part> open = new ArrayDeque<>();
        List<Node> top = new ArrayList<>();
        Matcher m = TAG.matcher(source);
        int at = 0;
        while (m.find()) {
            List<Node> into = open.isEmpty() ? top : open.peek().nodes();
            if (m.start() > at) {
                into.add(new Text(source.substring(at, m.start())));
            }
            at = m.end();
            String kind = m.group(1);
            String name = m.group(2);
            if (!arguments.contains(name)) {
                throw new IllegalArgumentException(
                        "placeholder " + m.group() + " names no declared argument " + arguments);
            }
            switch (kind) {
                case "" -> into.add(new Value(name));
                case "/" -> {
                    if (open.isEmpty() || !open.peek().name().equals(name)) {
                        throw new IllegalArgumentException(m.group() + " closes a part that is not open"
                                + (open.isEmpty() ? "" : "; open is '" + open.peek().name() + "'"));
                    }
                    open.pop();
                }
                default -> {
                    Part part = new Part(name, kind.equals("#"), new ArrayList<>());
                    into.add(part);
                    open.push(part);
                }
            }
        }
        if (!open.isEmpty()) {
            throw new IllegalArgumentException("the part of '" + open.peek().name() + "' is not closed");
        }
        if (at < source.length()) {
            top.add(new Text(source.substring(at)));
        }
        return new PromptTemplate(top);
    }

    /**
     * @param given the arguments that have a value; a missing or blank one counts as not
     * given
     */
    String render(Map<String, String> given) {
        StringBuilder out = new StringBuilder();
        render(nodes, given, out);
        return out.toString();
    }

    private static void render(List<Node> nodes, Map<String, String> given, StringBuilder out) {
        for (Node node : nodes) {
            switch (node) {
                case Text t -> out.append(t.text());
                case Value v -> out.append(given.getOrDefault(v.name(), ""));
                case Part p -> {
                    String value = given.get(p.name());
                    if ((value != null && !value.isBlank()) == p.whenGiven()) {
                        render(p.nodes(), given, out);
                    }
                }
            }
        }
    }

}

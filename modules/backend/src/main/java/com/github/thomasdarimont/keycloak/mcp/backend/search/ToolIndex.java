package com.github.thomasdarimont.keycloak.mcp.backend.search;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

/**
 * Deterministic lexical index over the tool catalog. The constants below are the scores
 * of the single kinds of match.
 */
public class ToolIndex {

    static final int EXACT_NAME = 100;
    static final int FUZZY_NAME = 50;
    static final int NAME_TOKEN = 10;
    static final int TITLE_TOKEN = 6;
    static final int SYNONYM_TOKEN = 6;
    static final int DESCRIPTION_TOKEN = 2;
    static final int CATEGORY_TOKEN = 4;
    static final int PREFIX_TOKEN = 3;

    private record Doc(ToolSpec spec, Set<String> nameTokens, Set<String> titleTokens, Set<String> synonymTokens,
            Set<String> descriptionTokens, Set<String> paramTokens, Set<String> categoryTokens, String shortName) {
    }

    private final List<Doc> docs = new ArrayList<>();
    private final Map<String, Doc> byName = new HashMap<>();

    public ToolIndex(Collection<ToolSpec> specs) {
        for (ToolSpec spec : specs) {
            String shortName = spec.name().startsWith("keycloak_") ? spec.name().substring(9) : spec.name();
            Doc doc = new Doc(spec, new HashSet<>(Tokenizer.tokens(shortName)),
                    new HashSet<>(Tokenizer.tokens(spec.title())), synonymTokens(spec.synonyms()),
                    // the category blurb lists verbs ("find, create, delete users") and
                    // is only weak evidence
                    new HashSet<>(Tokenizer.tokens(spec.description() + " " + spec.category().blurb())),
                    new HashSet<>(Tokenizer.tokens(String.join(" ", spec.parameterNames()))),
                    new HashSet<>(Tokenizer.tokens(spec.category().name())), shortName);
            docs.add(doc);
            byName.put(spec.name(), doc);
        }
    }

    private static Set<String> synonymTokens(List<String> synonyms) {
        Set<String> out = new HashSet<>();
        for (String s : synonyms) {
            out.addAll(Tokenizer.tokens(s));
        }
        return out;
    }

    public List<SearchHit> search(String query, Category category, int limit, Predicate<ToolSpec> visible) {
        List<String> qTokens = Tokenizer.tokens(query);
        String qName = query == null ? "" : normalizeName(query);
        List<SearchHit> hits = new ArrayList<>();
        for (Doc doc : docs) {
            if (category != null && doc.spec.category() != category) {
                continue;
            }
            if (visible != null && !visible.test(doc.spec)) {
                continue;
            }
            int score = score(doc, qTokens, qName);
            if (score > 0 || (qTokens.isEmpty() && category != null)) {
                hits.add(new SearchHit(doc.spec, score));
            }
        }
        // ties: reads before writes, then the tool whose name the query covers best
        // ("assign role to user" ->
        // user_role_assign rather than user_client_role_assign), then the name
        Map<String, Integer> unmatched = new HashMap<>();
        for (SearchHit h : hits) {
            Doc doc = byName.get(h.spec().name());
            int n = 0;
            for (String nt : doc.nameTokens) {
                if (!qTokens.contains(nt)) {
                    n++;
                }
            }
            unmatched.put(h.spec().name(), n);
        }
        hits.sort(Comparator.comparingInt(SearchHit::score)
            .reversed()
            .thenComparing(h -> h.spec().level())
            .thenComparingInt(h -> unmatched.get(h.spec().name()))
            .thenComparing(h -> h.spec().name()));
        return hits.size() > limit ? new ArrayList<>(hits.subList(0, limit)) : hits;
    }

    /** Closest tool names for "did you mean" on unknown names. */
    public List<SearchHit> similarNames(String name, int limit, Predicate<ToolSpec> visible) {
        String q = normalizeName(name);
        String qShort = q.startsWith("keycloak_") ? q.substring(9) : q;
        List<SearchHit> hits = new ArrayList<>();
        List<String> qTokens = Tokenizer.tokens(qShort);
        for (Doc doc : docs) {
            if (visible != null && !visible.test(doc.spec)) {
                continue;
            }
            int dist = Fuzzy.distance(qShort, doc.shortName, 4);
            int score = dist <= 4 ? (5 - dist) * 20 : 0;
            for (String t : qTokens) {
                if (doc.nameTokens.contains(t)) {
                    score += NAME_TOKEN;
                }
                else if (doc.synonymTokens.contains(t) || doc.titleTokens.contains(t)) {
                    score += TITLE_TOKEN;
                }
            }
            if (score > 0) {
                hits.add(new SearchHit(doc.spec, score));
            }
        }
        hits.sort(Comparator.comparingInt(SearchHit::score).reversed().thenComparing(h -> h.spec().name()));
        return hits.size() > limit ? new ArrayList<>(hits.subList(0, limit)) : hits;
    }

    private int score(Doc doc, List<String> qTokens, String qName) {
        int score = 0;
        if (!qName.isEmpty()) {
            if (qName.equals(doc.spec.name()) || qName.equals(doc.shortName)) {
                score += EXACT_NAME;
            }
            else if (qName.length() >= 6) {
                String qShort = qName.startsWith("keycloak_") ? qName.substring(9) : qName;
                if (Fuzzy.distance(qShort, doc.shortName, 2) <= 2) {
                    score += FUZZY_NAME;
                }
            }
        }
        for (String t : qTokens) {
            // each query token counts once, at the strongest field it occurs in; summing
            // fields let tools with
            // verbose titles, synonyms or descriptions outrank the tool whose name says
            // exactly that
            int best = 0;
            if (doc.nameTokens.contains(t)) {
                best = NAME_TOKEN;
            }
            else if (doc.titleTokens.contains(t)) {
                best = TITLE_TOKEN;
            }
            else if (doc.synonymTokens.contains(t)) {
                best = SYNONYM_TOKEN;
            }
            else if (doc.categoryTokens.contains(t)) {
                best = CATEGORY_TOKEN;
            }
            else if (doc.descriptionTokens.contains(t) || doc.paramTokens.contains(t)) {
                best = DESCRIPTION_TOKEN;
            }
            score += best;
            boolean matched = best > 0;
            if (!matched && t.length() >= 4) {
                // prefix match on name/title tokens: "auth" ~ "authenticator", "fed" ~
                // "federation"
                for (String nt : doc.nameTokens) {
                    if (nt.startsWith(t) || t.startsWith(nt) && nt.length() >= 4) {
                        score += PREFIX_TOKEN;
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    for (String st : doc.synonymTokens) {
                        if (st.startsWith(t) || t.startsWith(st) && st.length() >= 4) {
                            score += PREFIX_TOKEN;
                            break;
                        }
                    }
                }
            }
        }
        return score;
    }

    private static String normalizeName(String q) {
        return q.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
    }
}

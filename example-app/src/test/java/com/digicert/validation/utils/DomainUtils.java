package com.digicert.validation.utils;

import java.security.SecureRandom;
import java.util.List;
import java.util.Random;
import java.util.stream.IntStream;

public class DomainUtils {
    private static final Random random = new SecureRandom();

    private static final List<String> firstPiece = List.of(
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
            "lambda", "mu", "nu", "xi", "omicron", "pi", "rho", "sigma", "tau", "upsilon",
            "phi", "chi", "psi", "omega", "aqua", "terra", "sol", "luna", "nova", "stella",
            "astro", "cosmo", "galaxy", "nebula", "quasar", "pulsar", "comet", "meteor", "orbit", "eclipse",
            "zenith", "horizon", "vertex", "apex", "nadir", "zenith", "aphelion", "perihelion", "solstice", "equinox"
    );

    private static final List<String> secondPiece = List.of(
            "tech", "web", "cloud", "data", "byte", "bit", "code", "dev", "app",
            "soft", "ware", "sys", "info", "logic", "matrix", "node", "hub", "link", "port",
            "gate", "path", "route", "stream", "flow", "wave", "pulse", "signal", "band", "freq",
            "mod", "trans", "form", "gen", "sync", "core", "prime", "edge", "point", "zone",
            "field", "grid", "mesh", "web", "site", "page", "host", "serverWithData", "domain"
    );

    public static String getRandomDomainName(int numLabels, String tld) {
        StringBuilder domainName = new StringBuilder();

        // Include the TLD as a label, so go one less than the number of labels
        IntStream.rangeClosed(1, numLabels - 1).forEach(i -> {
            domainName.append(firstPiece.get(random.nextInt(firstPiece.size())));
            if (i == numLabels - 1) {
                domainName.append("-");
                domainName.append(secondPiece.get(random.nextInt(secondPiece.size())));
            }
            domainName.append(".");
        });
        return domainName.append(tld).toString();
    }
}

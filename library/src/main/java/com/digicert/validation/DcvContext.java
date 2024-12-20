package com.digicert.validation;

import com.digicert.validation.challenges.BasicRequestTokenValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The DcvContext provides dependency injection, allowing for easier testing of the various pieces
 * of the library. It initializes and holds references to various classes used throughout the application.
 * It is possible to have multiple contexts side by side with different configuration.
 */
@Slf4j
public class DcvContext {

    /** The DCV Configuration used by the context. */
    @Getter
    private final DcvConfiguration dcvConfiguration;

    /** A map of instances that have been created by the context. */
    private final HashMap<Class<?>, Object> instances = new HashMap<>();

    /**
     * This map is used for basic implementations of interfaces to only load if no custom implementation is provided.
     * <p>
     * When the BasicRequestTokenValidator class is instantiated, it also instantiates a BasicRequestTokenUtils
     * instance. That utils class requires a BouncyCastleProvider to be added as a security provider. By lazily loading
     * the validator, users of this library can avoid adding the BouncyCastleProvider as a security provider if they
     * provide their own implementation of the RequestTokenValidator interface.
     */
    private final Map<Class<?>, Class<?>> lazyLoadImplementations = Map.of(
            RequestTokenValidator.class, BasicRequestTokenValidator.class
    );

    /**
     * Retrieves an instance of the specified class. If an instance already exists, it returns the cached instance.
     * If the class is found in the DCV Configuration, it caches and returns it. Otherwise, it instantiates the class,
     * caches it, and returns it.
     *
     * @param classType the class to retrieve or instantiate
     * @param <T>    the type of the class
     * @return an instance of the specified class
     * @throws RuntimeException if the class cannot be instantiated
     */
    @SuppressWarnings("unchecked")
    public <T> T get(Class<T> classType) {
        try {
            // If we already have an instance of the desired class, return it
            if (instances.containsKey(classType)) {
                return (T) instances.get(classType);
            }

            // If the desired class should come from the DCV Configuration, cache it and return it
            Optional<Field> fieldOpt = Arrays.stream(DcvConfiguration.class.getDeclaredFields())
                    .filter(f -> f.getType().equals(classType))
                    .findFirst();

            if (fieldOpt.isPresent()) {
                Field field = fieldOpt.get();
                field.setAccessible(true);

                Object configObject = field.get(dcvConfiguration);
                if (configObject != null) {
                    instances.put(classType, configObject);
                    return (T) configObject;
                }
            }

            // With the lazyLoadImplementations map as an override, instantiate the desired class, cache it, and return it
            Object foundClass;
            if (lazyLoadImplementations.containsKey(classType)) {
                foundClass = lazyLoadImplementations.getOrDefault(classType, classType).getConstructor().newInstance();
            } else {
                foundClass = classType.getConstructor(DcvContext.class).newInstance(this);
            }
            instances.put(classType, foundClass);
            return (T) foundClass;

        } catch (IllegalAccessException |
                 NoSuchMethodException |
                 InvocationTargetException |
                 InstantiationException e) {
            throw new IllegalStateException("Unable to instantiate the DCV Context", e);
        }
    }

    /** Default constructor that initializes the context with a default DCV Configuration. */
    public DcvContext() {
        this(new DcvConfiguration.DcvConfigurationBuilder().build());
    }

    /**
     * Constructor that initializes the context with the provided DCV Configuration.
     *
     * @param dcvConfiguration the DCV Configuration to use
     */
    public DcvContext(DcvConfiguration dcvConfiguration) {
        this.dcvConfiguration = dcvConfiguration;
    }
}
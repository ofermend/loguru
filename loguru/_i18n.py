"""Internal i18n support for loguru.

This module provides a small ``_()`` translation helper used to look up
user-facing strings (error messages, deprecation warnings, etc.) in the
language selected by the ``LOGURU_LANG`` environment variable. When the
variable is unset, empty, or names an unknown language, ``_(s)`` returns
the original English string unchanged so existing behaviour is preserved.

Translation tables are plain ``dict[str, str]`` mappings keyed by the exact
English source string (printf-style placeholders such as ``%s``, ``%d`` and
``%r`` are preserved verbatim in every translation).

The module deliberately uses an unannotated source signature so it remains
importable on Python 3.5 (Loguru's lower bound), matching the rest of the
package.
"""

from os import environ

_FRENCH = {
    # --- loguru/_logger.py ---
    "An event loop is required to add a coroutine sink with `enqueue=True`, "
    "but none has been passed as argument and none is currently running.": (
        "Une boucle d'événements est requise pour ajouter un puits de coroutine "
        "avec `enqueue=True`, mais aucune n'a été fournie en argument et aucune "
        "n'est actuellement en cours d'exécution."
    ),
    "Cannot log to objects of type '%s'": "Impossible de journaliser vers des objets de type '%s'",
    "add() got an unexpected keyword argument '%s'": (
        "add() a reçu un argument nommé inattendu '%s'"
    ),
    "The filter dict contains an invalid module, "
    "it should be a string (or None), not: '%s'": (
        "Le dictionnaire de filtre contient un module invalide, "
        "il devrait être une chaîne (ou None), pas : '%s'"
    ),
    "The filter dict contains a module '%s' associated to a level name "
    "which does not exist: '%s'": (
        "Le dictionnaire de filtre contient un module '%s' associé à un nom de niveau "
        "qui n'existe pas : '%s'"
    ),
    "The filter dict contains a module '%s' associated to an invalid level, "
    "it should be an integer, a string or a boolean, not: '%s'": (
        "Le dictionnaire de filtre contient un module '%s' associé à un niveau invalide, "
        "il devrait être un entier, une chaîne ou un booléen, pas : '%s'"
    ),
    "The filter dict contains a module '%s' associated to an invalid level, "
    "it should be a positive integer, not: '%d'": (
        "Le dictionnaire de filtre contient un module '%s' associé à un niveau invalide, "
        "il devrait être un entier positif, pas : '%d'"
    ),
    "The built-in 'filter()' function cannot be used as a 'filter' parameter, "
    "this is most likely a mistake (please double-check the arguments passed "
    "to 'logger.add()').": (
        "La fonction native 'filter()' ne peut pas être utilisée comme paramètre 'filter', "
        "il s'agit très probablement d'une erreur (veuillez revérifier les arguments "
        "passés à 'logger.add()')."
    ),
    "Invalid filter, it should be a function, a string or a dict, not: '%s'": (
        "Filtre invalide, il devrait être une fonction, une chaîne ou un dictionnaire, "
        "pas : '%s'"
    ),
    "Invalid level, it should be an integer or a string, not: '%s'": (
        "Niveau invalide, il devrait être un entier ou une chaîne, pas : '%s'"
    ),
    "Invalid level value, it should be a positive integer, not: %d": (
        "Valeur de niveau invalide, elle devrait être un entier positif, pas : %d"
    ),
    "Invalid format, color markups could not be parsed correctly": (
        "Format invalide, les balises de couleur n'ont pas pu être analysées correctement"
    ),
    "The built-in 'format()' function cannot be used as a 'format' parameter, "
    "this is most likely a mistake (please double-check the arguments passed "
    "to 'logger.add()').": (
        "La fonction native 'format()' ne peut pas être utilisée comme paramètre 'format', "
        "il s'agit très probablement d'une erreur (veuillez revérifier les arguments "
        "passés à 'logger.add()')."
    ),
    "Invalid format, it should be a string or a function, not: '%s'": (
        "Format invalide, il devrait être une chaîne ou une fonction, pas : '%s'"
    ),
    "Invalid context, it should be a string or a multiprocessing context, "
    "not: '%s'": (
        "Contexte invalide, il devrait être une chaîne ou un contexte multiprocessing, "
        "pas : '%s'"
    ),
    "Invalid handler id, it should be an integer as returned "
    "by the 'add()' method (or None), not: '%s'": (
        "Identifiant de gestionnaire invalide, il devrait être un entier tel que retourné "
        "par la méthode 'add()' (ou None), pas : '%s'"
    ),
    "There is no existing handler with id %d": (
        "Aucun gestionnaire n'existe avec l'identifiant %d"
    ),
    "Invalid object decorated with 'catch()', it must be a function, "
    "not a class (tried to wrap '%s')": (
        "Objet invalide décoré avec 'catch()', ce doit être une fonction, "
        "pas une classe (tentative d'encapsulation de '%s')"
    ),
    "The 'ansi' parameter is deprecated, please use 'colors' instead": (
        "Le paramètre 'ansi' est obsolète, veuillez utiliser 'colors' à la place"
    ),
    "Invalid level name, it should be a string, not: '%s'": (
        "Nom de niveau invalide, il devrait être une chaîne, pas : '%s'"
    ),
    "Level '%s' does not exist": "Le niveau '%s' n'existe pas",
    "Level '%s' does not exist, you have to create it by specifying a level no": (
        "Le niveau '%s' n'existe pas, vous devez le créer en spécifiant un numéro de niveau"
    ),
    "Level '%s' already exists, you can't update its severity no": (
        "Le niveau '%s' existe déjà, vous ne pouvez pas mettre à jour son numéro de sévérité"
    ),
    "Invalid level no, it should be an integer, not: '%s'": (
        "Numéro de niveau invalide, il devrait être un entier, pas : '%s'"
    ),
    "Invalid level no, it should be a positive integer, not: %d": (
        "Numéro de niveau invalide, il devrait être un entier positif, pas : %d"
    ),
    "Invalid name, it should be a string (or None), not: '%s'": (
        "Nom invalide, il devrait être une chaîne (ou None), pas : '%s'"
    ),
    "Invalid file, it should be a string path or a file object, not: '%s'": (
        "Fichier invalide, il devrait être un chemin sous forme de chaîne "
        "ou un objet fichier, pas : '%s'"
    ),
    "Invalid cast, it should be a function or a dict, not: '%s'": (
        "Conversion invalide, elle devrait être une fonction ou un dictionnaire, " "pas : '%s'"
    ),
    "Invalid pattern, it should be a string or a compiled regex, not: '%s'": (
        "Motif invalide, il devrait être une chaîne ou une regex compilée, pas : '%s'"
    ),
    "The message can't be formatted: 'record' shall not be used as a keyword "
    "argument while logger has been configured with '.opt(record=True)'": (
        "Le message ne peut pas être formaté : 'record' ne doit pas être utilisé "
        "comme argument nommé lorsque le logger a été configuré avec '.opt(record=True)'"
    ),
    "The 'start()' method is deprecated, please use 'add()' instead": (
        "La méthode 'start()' est obsolète, veuillez utiliser 'add()' à la place"
    ),
    "The 'stop()' method is deprecated, please use 'remove()' instead": (
        "La méthode 'stop()' est obsolète, veuillez utiliser 'remove()' à la place"
    ),
    "An error has been caught in function '{record[function]}', "
    "process '{record[process].name}' ({record[process].id}), "
    "thread '{record[thread].name}' ({record[thread].id}):": (
        "Une erreur a été interceptée dans la fonction '{record[function]}', "
        "processus '{record[process].name}' ({record[process].id}), "
        "fil d'exécution '{record[thread].name}' ({record[thread].id}) :"
    ),
    # --- loguru/_defaults.py ---
    "Invalid environment variable '%s' (expected a boolean): '%s'": (
        "Variable d'environnement invalide '%s' (booléen attendu) : '%s'"
    ),
    "Invalid environment variable '%s' (expected an integer): '%s'": (
        "Variable d'environnement invalide '%s' (entier attendu) : '%s'"
    ),
    "The requested type '%s' is not supported": ("Le type demandé '%s' n'est pas pris en charge"),
    # --- loguru/_asyncio_loop.py ---
    "There is no running event loop": "Aucune boucle d'événements n'est en cours d'exécution",
    # --- loguru/_handler.py ---
    "Could not acquire internal lock because it was already in use (deadlock avoided). "
    "This likely happened because the logger was re-used inside a sink, a signal "
    "handler or a '__del__' method. This is not permitted because the logger and its "
    "handlers are not re-entrant.": (
        "Impossible d'acquérir le verrou interne car il était déjà utilisé "
        "(interblocage évité). Cela s'est probablement produit parce que le logger "
        "a été réutilisé à l'intérieur d'un puits, d'un gestionnaire de signal ou "
        "d'une méthode '__del__'. Ce n'est pas autorisé car le logger et ses "
        "gestionnaires ne sont pas réentrants."
    ),
    "Failed to format log record: key %s not found.\n"
    "Verify that the format string %r only references valid record keys "
    "and that all required extra keys are present.\n"
    "Available records key are: %s.\n"
    "While using a dynamic formatter as a function, note that it must return "
    "the string to be formatted, not an already formatted message.\n"
    "To include custom data, use 'logger.bind(key=value)' and reference it "
    "as '{extra[key]}' in the format string.": (
        "Échec du formatage de l'enregistrement de log : clé %s introuvable.\n"
        "Vérifiez que la chaîne de format %r ne référence que des clés "
        "d'enregistrement valides et que toutes les clés supplémentaires requises "
        "sont présentes.\n"
        "Les clés d'enregistrement disponibles sont : %s.\n"
        "Lors de l'utilisation d'un formateur dynamique sous forme de fonction, "
        "notez qu'il doit retourner la chaîne à formater, et non un message "
        "déjà formaté.\n"
        "Pour inclure des données personnalisées, utilisez 'logger.bind(key=value)' "
        "et référencez-la sous la forme '{extra[key]}' dans la chaîne de format."
    ),
    # --- loguru/_datetime.py ---
    "Invalid time format: the provided format string contains more than six successive "
    "'S' characters. This may be due to an attempt to use nanosecond precision, which "
    "is not supported.": (
        "Format temporel invalide : la chaîne de format fournie contient plus de six "
        "caractères 'S' successifs. Cela peut être dû à une tentative d'utiliser la "
        "précision à la nanoseconde, qui n'est pas prise en charge."
    ),
    # --- loguru/_file_sink.py ---
    "Must provide at least one rotation condition": (
        "Vous devez fournir au moins une condition de rotation"
    ),
    "Cannot parse rotation from: '%s'": "Impossible d'analyser la rotation depuis : '%s'",
    "Cannot infer rotation for objects of type: '%s'": (
        "Impossible de déduire la rotation pour les objets de type : '%s'"
    ),
    "Cannot parse retention from: '%s'": "Impossible d'analyser la rétention depuis : '%s'",
    "Cannot infer retention for objects of type: '%s'": (
        "Impossible de déduire la rétention pour les objets de type : '%s'"
    ),
    "Invalid compression format: '%s'": "Format de compression invalide : '%s'",
    "Cannot infer compression for objects of type: '%s'": (
        "Impossible de déduire la compression pour les objets de type : '%s'"
    ),
    # --- loguru/_colorizer.py ---
    "The logging message could not be formatted with the provided arguments.\n"
    "Common causes include:\n"
    "  - The message contains unmatched or malformed curly braces.\n"
    "  - Positional or keyword arguments are missing for the placeholders.\n"
    "  - The message is not a string.\n"
    "  - f-strings were used causing double interpolation.\n"
    "  - Contextual values were passed via kwargs but not meant for formatting.\n"
    "To avoid this, consider:\n"
    "  - Escaping non-formatting braces by doubling them.\n"
    "  - Avoiding f-string in the logged message.\n"
    "  - Using `logger.bind()` for structured context instead of kwargs.\n": (
        "Le message de log n'a pas pu être formaté avec les arguments fournis.\n"
        "Les causes courantes sont :\n"
        "  - Le message contient des accolades non appariées ou malformées.\n"
        "  - Des arguments positionnels ou nommés manquent pour les espaces réservés.\n"
        "  - Le message n'est pas une chaîne.\n"
        "  - Des f-strings ont été utilisées, provoquant une double interpolation.\n"
        "  - Des valeurs contextuelles ont été passées via kwargs sans être destinées "
        "au formatage.\n"
        "Pour éviter cela, vous pouvez :\n"
        "  - Échapper les accolades non destinées au formatage en les doublant.\n"
        "  - Éviter les f-strings dans le message journalisé.\n"
        "  - Utiliser `logger.bind()` pour un contexte structuré au lieu de kwargs.\n"
    ),
    "The '<level>' color tag is not allowed in this context, "
    "it has not yet been associated to any color value.": (
        "La balise de couleur '<level>' n'est pas autorisée dans ce contexte, "
        "elle n'a pas encore été associée à une valeur de couleur."
    ),
    'Closing tag "%s" violates nesting rules': (
        'La balise de fermeture "%s" viole les règles d\'imbrication'
    ),
    'Closing tag "%s" has no corresponding opening tag': (
        "La balise de fermeture \"%s\" n'a pas de balise d'ouverture correspondante"
    ),
    'Tag "%s" does not correspond to any known color directive, '
    "make sure you have not misspelled it (or prepend '\\' to escape it)": (
        'La balise "%s" ne correspond à aucune directive de couleur connue, '
        "assurez-vous de ne pas l'avoir mal orthographiée "
        "(ou préfixez-la avec '\\' pour l'échapper)"
    ),
    'Opening tag "<%s>" has no corresponding closing tag': (
        "La balise d'ouverture \"<%s>\" n'a pas de balise de fermeture correspondante"
    ),
    "Max string recursion exceeded": "Récursion maximale de chaîne dépassée",
    "cannot switch from manual field "
    "specification to automatic field "
    "numbering": (
        "impossible de basculer de la spécification manuelle des champs "
        "à la numérotation automatique des champs"
    ),
    # --- loguru/_string_parsers.py ---
    "Invalid float value while parsing size: '%s'": (
        "Valeur flottante invalide lors de l'analyse de la taille : '%s'"
    ),
    "Invalid float value while parsing duration: '%s'": (
        "Valeur flottante invalide lors de l'analyse de la durée : '%s'"
    ),
    "Invalid unit value while parsing duration: '%s'": (
        "Valeur d'unité invalide lors de l'analyse de la durée : '%s'"
    ),
    "Invalid weekday value while parsing day (expected [0-6]): '%d'": (
        "Valeur de jour de la semaine invalide lors de l'analyse du jour " "(attendu [0-6]) : '%d'"
    ),
    "Unrecognized format while parsing time: '%s'": (
        "Format non reconnu lors de l'analyse de l'heure : '%s'"
    ),
    "Unparsable day": "Jour non analysable",
    "Invalid day while parsing daytime: '%s'": (
        "Jour invalide lors de l'analyse de la date/heure : '%s'"
    ),
    "Unparsable time": "Heure non analysable",
    "Invalid time while parsing daytime: '%s'": (
        "Heure invalide lors de l'analyse de la date/heure : '%s'"
    ),
}

_TRANSLATIONS = {
    "fr": _FRENCH,
}


def _(s):
    """Return the translation of ``s`` for the language in ``LOGURU_LANG``.

    Falls back to ``s`` unchanged when the environment variable is unset or
    empty, when it names an unknown language, or when no translation exists
    for ``s`` in the selected table. The lookup is performed on every call so
    callers can switch languages by mutating the process environment.
    """
    lang = environ.get("LOGURU_LANG")
    if not lang:
        return s
    table = _TRANSLATIONS.get(lang)
    if table is None:
        return s
    return table.get(s, s)

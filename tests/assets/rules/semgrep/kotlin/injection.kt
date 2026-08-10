
fun sql(db: android.database.sqlite.SQLiteDatabase, q: String) {
    // ruleid:android_kotlin_sql_raw_query
    db.rawQuery(q, null)
    // ruleid:android_kotlin_sql_raw_query
    db.execSQL(q)
}

fun jackson(mapper: com.fasterxml.jackson.databind.ObjectMapper) {
    // ruleid:android_kotlin_jackson_deserialize
    mapper.enableDefaultTyping()
}

fun commandInjection(foo: String, input: String) {
    // ruleid:android_kotlin_command_injection
    Runtime.getRuntime().exec("ping somewhere.com" + foo)
    // ok:android_kotlin_command_injection
    Runtime.getRuntime().exec("ping somewhere.com")

    val runtime = Runtime.getRuntime()
    // ruleid:android_kotlin_command_injection_warning
    runtime.exec("/bin/sh -c some_tool" + input)
    // ruleid:android_kotlin_command_injection_warning
    runtime.loadLibrary(String.format("%s.dll", input))
    // ok:android_kotlin_command_injection_warning
    runtime.exec("echo 'blah'")
}

fun objectDeser(receivedFile: java.io.InputStream): Any {
    // ruleid:android_kotlin_object_deserialization
    val input = ObjectInputStream(receivedFile)
    return input.readObject()
}

fun xxeBad(): XMLInputFactory {
    // ruleid:android_kotlin_xmlinputfactory_xxe
    val xmlInputFactory = XMLInputFactory.newFactory()
    return xmlInputFactory
}

fun xxeGood(): XMLInputFactory {
    val xmlInputFactory = XMLInputFactory.newFactory()
    // ok:android_kotlin_xmlinputfactory_xxe
    xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false)
    return xmlInputFactory
}

fun xxeEnabled(factory: XMLInputFactory) {
    // ruleid:android_kotlin_xmlinputfactory_xxe_enabled
    factory.setProperty("javax.xml.stream.isSupportingExternalEntities", true)
    // ok:android_kotlin_xmlinputfactory_xxe_enabled
    factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false)
}

// ruleid:android_kotlin_xml_decoder_xxe
fun xmlDecoderBad(ins: java.io.InputStream): Any {
    val decoder = XMLDecoder(ins)
    return decoder.readObject()
}

// ok:android_kotlin_xml_decoder_xxe
fun xmlDecoderGood(): Any {
    val decoder = XMLDecoder("<safe>XML</safe>")
    return decoder.readObject()
}


/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.repository.directory;

import com.intel.kms.repository.Repository;
import com.intel.mtwilson.codec.JacksonCodec;
import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FileUtils;

/**
 *
 * @author jbuhacoff
 */
public class JacksonFileRepository<T,String> implements Repository<T,String> {
    private File directory;
    private JacksonCodec jackson;

    public JacksonFileRepository(File directory) {
        this.directory = directory;
        this.jackson = new JacksonCodec();
    }
    
    private File locate(String id) {
        return new File(directory.getAbsolutePath()+File.separator+id);
    }

    @Override
    public void create(String id, T item) {
        try {
            byte[] json = jackson.encode(item); // writeValueAsString(item); // throws JsonProcessingException (subclass of IOException)
            FileUtils.writeByteArrayToFile(locate(id), json);
        }
        catch(IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public void store(String id, T item) {
        try {
            byte[] json = jackson.encode(item); // writeValueAsString(item); // throws JsonProcessingException (subclass of IOException)
            FileUtils.writeByteArrayToFile(locate(id), json);
        }
        catch(IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public T retrieve(String id) {
        try {
            byte[] json = FileUtils.readFileToByteArray(locate(id));
            Object item = jackson.decode(json);
            return (T)item;
        }
        catch(IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public void delete(String id) {
        locate(id).delete();
    }
/*
    @Override
    public Collection search(Map criteria) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
 */
}

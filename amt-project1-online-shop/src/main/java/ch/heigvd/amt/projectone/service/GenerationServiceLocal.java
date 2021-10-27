package ch.heigvd.amt.projectone.service;

import javax.ejb.Local;

@Local
public interface GenerationServiceLocal {

    void generate(int count);
}

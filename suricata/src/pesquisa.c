#include "pesquisa.h"

void logFitness(void *key, int signatureID, int fitness){
    char *keyword = (char *) key;
    fitness = abs(fitness);
    //if (fitness == 0)
    printf("SID: %d - %s keyword fitness: %d\n", signatureID, keyword, fitness);
}
#include "pesquisa.h"

void logFitness(void *key, int signatureID, float fitness){
    FILE *fp = fopen("./rulesFitness.txt", "a");

    char *keyword = (char *) key;
    //fitness = abs(fitness);

    fprintf(fp, " - %s: %f", keyword, fitness);
    fclose(fp);
    //if (fitness == 0)
    printf("SID: %d - %s keyword fitness: %f\n", signatureID, keyword, fitness);
}
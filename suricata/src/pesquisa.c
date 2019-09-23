#include "pesquisa.h"
#include "string.h"

void logFitness(void *key, int signatureID, float fitness){
    FILE *fp = fopen("./rulesFitness.txt", "a");

    char *keyword = (char *) key;
    //fitness = abs(fitness);

    if(strcmp(keyword, "threshold") == 0){
        fseek(fp, -2, SEEK_END);
    }

    fprintf(fp, " - %s: %f", keyword, fitness);
    fclose(fp);
    printf("SID: %d - %s keyword fitness: %f\n", signatureID, keyword, fitness);
}
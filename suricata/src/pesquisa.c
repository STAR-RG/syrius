#include "pesquisa.h"
#include "string.h"

void logFitness(void *key, int signatureID, double fitness){
    FILE *fp = fopen("./rulesFitness.txt", "a");

    char *keyword = (char *) key;
    //fitness = abs(fitness);

    fprintf(fp, " - %s: %lf", keyword, fitness);

    if(strcmp(keyword, "threshold") == 0){
        //fprintf(fp, "\n");
    }

    fflush(fp);

    fclose(fp);
    printf("SID: %d - %s keyword fitness: %lf\n", signatureID, keyword, fitness);
}
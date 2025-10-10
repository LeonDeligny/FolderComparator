Règles pour les Motifs d'Exclusion (file2exclude.txt)

1. Séparateur de Chemins (/) :
	- Utilisez toujours le slash (/) comme séparateur de répertoire, quel que soit votre système d'exploitation. Le script normalisera les chemins internes en conséquence.

2. Chemins Relatifs :
	- Tous les motifs sont relatifs à la racine du dossier scanné (source ou cible). Ils ne commencent pas par / (ce qui impliquerait la racine du système de fichiers).
	- Exemple : Pour exclure un dossier build situé directement sous la racine scannée, utilisez build/. Pour un fichier config.tmp à la racine, utilisez config.tmp.

3. Joker * (Astérisque Simple) :
	-L'astérisque (*) correspond à zéro ou plusieurs caractères au sein d'un seul composant de chemin (un nom de fichier ou un nom de répertoire). Il ne correspond pas aux séparateurs de chemin (/).
	- Exemple : Le motif *.log exclura fichier.log mais pas dossier/fichier.log.
	- Exemple : Le motif temp_* exclura temp_file.txt ou temp_dir/ (s'il est appliqué comme pattern de dossier).

4. Joker ** (Double Astérisque - Correspondance Récursive) :
	- Le double astérisque (**) correspond à zéro ou plusieurs répertoires et sous-répertoires. Il peut correspondre aux séparateurs de chemin (/). C'est l'option à utiliser pour l'exclusion récursive à n'importe quel niveau.
	- Exemple : **/cache/ exclura tout dossier nommé cache et tout son contenu, quel que soit son niveau d'imbrication (projet/cache/, src/app/cache/un/autre/dossier/).
	- Exemple : **/rapport.pdf exclura tout fichier rapport.pdf trouvé n'importe où dans la hiérarchie.

5. Motifs de Répertoire (terminant par /) :
	- Un motif se terminant explicitement par un slash (/) indique un répertoire. Ce motif doit correspondre au répertoire lui-même et à tout son contenu de manière récursive.
	- Exemple : logs/ exclura le dossier logs (s'il est à la racine scannée) ainsi que logs/app.log, logs/backup/ etc.
	- Exemple : **/node_modules/ exclura tous les dossiers node_modules et tout ce qu'ils contiennent, où qu'ils se trouvent.

6. Motifs de Fichier (sans / final) :
	- Un motif ne se terminant PAS par un slash (/) est traité comme un motif de fichier. Il correspond aux fichiers et aux liens symboliques pointant vers des fichiers.
	- Exemple : .gitignore exclura un fichier nommé .gitignore, mais pas dossier/.gitignore.
	- Exemple : *.bak exclura tous les fichiers d'extension .bak, mais pas dossier/*.bak.
	- Exemple : **/temp.txt exclura un fichier temp.txt n'importe où.

7. Commentaires et Lignes Vides :
	- Les lignes commençant par # sont considérées comme des commentaires et sont ignorées. Les lignes vides sont également ignorées.

8. Sensibilité à la Casse :
	- Les motifs sont sensibles à la casse (par exemple, TEMP/ n'exclura pas temp/). C'est le comportement par défaut des expressions régulières Python.
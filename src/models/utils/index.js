const { globSync } = require("glob");
const { basename, extname } = require("path");

const appModelsFiles = globSync("src/models/app/**/*.js");

const pattern = "src/models/app/**/*.js";

const modelFiles = globSync(pattern).map((filePath) => {
  const fileNameWithExtension = basename(filePath);
  const fileNameWithoutExtension = fileNameWithExtension.replace(
    extname(filePath),
    ""
  );

  return fileNameWithoutExtension;
});

const controllersList = [];
const appModelsList = [];
const entityList = [];
const routesList = [];

for (const filePath in appModelsFiles) {
  const fileNameWithExtension = extname(filePath);
  const fileNameWithoutExtension = fileNameWithExtension.replace(
    extname(fileNameWithExtension),
    ""
  );

  const firstChar = fileNameWithoutExtension.charAt(0);
  const modelName = fileNameWithoutExtension.replace(
    firstChar,
    firstChar.toUpperCase()
  );
  const fileNameLowerCaseFirstChar = fileNameWithoutExtension.replace(
    firstChar,
    firstChar.toLowerCase()
  );
  const entity = fileNameWithoutExtension.toLowerCase();

  controllerName = fileNameLowerCaseFirstChar + "Controller";
  controllersList.push(controllerName);
  appModelsList.push(modelName);
  entityList.push(entity);

  const route = {
    entity: entity,
    modelName: modelName,
    controllerName: controllerName,
  };
  routesList.push(route);
}

module.exports = {
  controllersList,
  appModelsList,
  modelFiles,
  entityList,
  routesList,
};

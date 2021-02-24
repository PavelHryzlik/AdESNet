using System;
using System.IO;
using System.Reflection;

namespace AdESNet.Common
{
    public static class CLRLoader
    {
        private static Assembly cLRLibrary;
        public static Assembly CLRLibrary => cLRLibrary ?? (cLRLibrary = LoadCLRLibrary(BaseConstants.AdESNetCLRName));

        private static Assembly cLRFrameworkLibrary;
        public static Assembly CLRFrameworkLibrary => cLRFrameworkLibrary ?? (cLRFrameworkLibrary = LoadCLRLibrary(BaseConstants.AdESNetCLRFrameworkName));

        static Assembly LoadCLRLibrary(string libraryName)
        {
            string dir = Path.GetDirectoryName(
                Assembly.GetExecutingAssembly().Location);

            try
            {
                return Environment.Is64BitProcess
                    ? Assembly.LoadFile(Path.Combine(dir, BaseConstants.AdESNetCLRDirX64, libraryName))
                    : Assembly.LoadFile(Path.Combine(dir, BaseConstants.AdESNetCLRDirX86, libraryName));
            }
            catch (FileNotFoundException e)
            {
                return Environment.Is64BitProcess
                    ? Assembly.LoadFile(Path.Combine(dir, libraryName))
                    : Assembly.LoadFile(Path.Combine(dir, libraryName));
            }
            catch
            {
                throw;
            }
        }

        public static dynamic CreateCLRInstance(this Assembly assembly, string className)
        {
            var classType = assembly.GetType(className);
            return Activator.CreateInstance(classType);
        }
    }
}
